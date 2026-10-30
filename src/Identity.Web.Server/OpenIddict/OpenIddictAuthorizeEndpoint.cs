using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore; // OpenIddictServerAspNetCoreHelpers.GetOpenIddictServerRequest lives here.
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Norse.Abstractions.Components.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     The authorize endpoint (2026-10-29 OpenIddict spec §5.2), a passthrough: OpenIddict has already required a
///     registered client, an exact-match redirect URI, <c>response_type=code</c> and an S256 PKCE challenge, and refused
///     <c>prompt=none</c> beside any other prompt value, before this runs. It then decides in the spec's order: read the
///     Identity cookie and re-read its user; decide whether re-authentication is required; answer <c>login_required</c> for
///     <c>prompt=none</c>; otherwise honor a bound <c>norse_reauth</c> marker or challenge with a fresh one; refuse a
///     non-implicit consent; mint the principal (<see cref="UserPrincipalFactory" />) under one ad-hoc authorization.
/// </summary>
/// <remarks>
///     <para>
///         <b>One source.</b> Every decision reads OpenIddict's request parameters, never <c>Request.Query</c> or the form:
///         OpenIddict builds the request from the query (GET) or the form (POST), whose keys ASP.NET Core merges ignoring
///         case (every value kept, under one spelling: RC3 keeps the later one), and stores them under ordinal names, a
///         repeated name as an array.
///     </para>
///     <para>
///         <b>Ambiguity is refused, never resolved</b> (<c>invalid_request</c>, before a marker is minted): OpenIddict reads a
///         repeated singular parameter as absent rather than refusing it, so a repeated <c>prompt</c> or <c>max_age</c>
///         would otherwise drop a re-authentication requirement; and a differently cased spelling of any singular parameter
///         (the marker's included) is refused, because the merge can file the exact one under the variant's key (I1). <c>max_age</c> is read raw: digits only, since
///         OpenIddict's own conversion is a lenient <see cref="long.TryParse(string, out long)" />.
///     </para>
///     <para>
///         <b>T4-6:</b> a re-entry <see cref="ReturnUrls.Resolve" /> would not honor (too long, chiefly) is refused before the
///         challenge rather than landing the user on the app root. <b>T4-7:</b> a posted request re-enters as the GET form
///         of the same parameters, under the same hash. <b>T4-8:</b> the minted stamp is the cookie's.
///     </para>
///     <para>
///         <b>The cookie is not the user</b> (final I1): the cookie handler re-validates the stamp only once its interval
///         has passed, so after authenticating the cookie the endpoint re-reads the user through
///         <c>userManager.Outcome</c> (untracked, current). A user that is gone (<c>NotFound</c>), erased, or carries a
///         stamp other than the cookie's is no principal: challenged, or <c>login_required</c> under <c>prompt=none</c>,
///         so no authorization or code row names an erased subject and a stamp-rotated cookie never mints a code the
///         exchange would refuse. A lockout is not a reason (Buvy's lockout ruling: it blocks credential sign-in only).
///         Any other read failure is an invariant violation (500).
///     </para>
/// </remarks>
static class OpenIddictAuthorizeEndpoint
{
	/// <summary>How far in the future a cookie's <c>auth_time</c> may sit before it counts as stale.</summary>
	internal static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

	/// <summary>The prefix of a marker's key in the one-shot ledger (the ledger hashes the key itself).</summary>
	internal const string LedgerPrefix = "norse_reauth:";

	// Every parameter OIDC defines as single-valued that this endpoint or OpenIddict reads, and the marker itself. Looked up
	// ignoring case, so a case-variant spelling is found and refused (I1).
	static readonly HashSet<string> _singular = new(StringComparer.OrdinalIgnoreCase)
	{
		OpenIddictConstants.Parameters.AcrValues,
		OpenIddictConstants.Parameters.Claims,
		OpenIddictConstants.Parameters.ClientId,
		OpenIddictConstants.Parameters.CodeChallenge,
		OpenIddictConstants.Parameters.CodeChallengeMethod,
		OpenIddictConstants.Parameters.Display,
		OpenIddictConstants.Parameters.IdTokenHint,
		OpenIddictConstants.Parameters.LoginHint,
		OpenIddictConstants.Parameters.MaxAge,
		OpenIddictConstants.Parameters.Nonce,
		OpenIddictConstants.Parameters.Prompt,
		OpenIddictConstants.Parameters.RedirectUri,
		OpenIddictConstants.Parameters.Request,
		OpenIddictConstants.Parameters.RequestUri,
		OpenIddictConstants.Parameters.ResponseMode,
		OpenIddictConstants.Parameters.ResponseType,
		OpenIddictConstants.Parameters.Scope,
		OpenIddictConstants.Parameters.State,
		OpenIddictConstants.Parameters.UiLocales,
		AuthorizeTransaction.MarkerParameter
	};

	internal static async Task<IResult> Handle(HttpContext context, IOpenIddictApplicationManager applications,
		IOpenIddictAuthorizationManager authorizations, UserManager<NorseUser> userManager, ReauthMarkers markers,
		IPasskeyChallengeLedger ledger, TimeProvider clock, IOptions<IdentityOptions> identityOptions)
	{
		var request = context.GetOpenIddictServerRequest() ??
			throw new InvalidOperationException("The OpenIddict request cannot be retrieved.");
		List<KeyValuePair<string, StringValues>> parameters =
			[.. request.GetParameters().Select(static parameter =>
				new KeyValuePair<string, StringValues>(parameter.Key, (StringValues)parameter.Value))];

		if (!TryReadMaxAge(parameters, out var maxAge) || IsAmbiguous(parameters))
			return Error(OpenIddictConstants.Errors.InvalidRequest);

		// 1. Read the authentication: the Identity cookie, by name. No principal, or a stale one.
		var now = clock.GetUtcNow();
		var claimTypes = identityOptions.Value.ClaimsIdentity;
		var authentication = await context.AuthenticateAsync(IdentityConstants.ApplicationScheme).ConfigureAwait(false);
		var principal = authentication.Succeeded ? authentication.Principal : null;
		Guid? userId = principal?.FindAll(claimTypes.UserIdClaimType).Take(2).ToList() is [var id]
			&& Guid.TryParse(id.Value, out var parsed) ?
				parsed :
				null;
		var stamp = principal?.FindAll(claimTypes.SecurityStampClaimType).Take(2).ToList() is [var stampClaim]
			&& !string.IsNullOrEmpty(stampClaim.Value) ?
				stampClaim.Value :
				null;
		// The cookie is not the user (final I1): one gone, erased or carrying another stamp is no principal.
		if (userId is not null && stamp is not null
			&& !await IsCurrentAsync(userManager, userId.Value, stamp, context.RequestAborted).ConfigureAwait(false))
			(principal, userId, stamp) = (null, null, null);
		long? authTime = userId is not null && stamp is not null ? ReadAuthTime(principal!, now) : null;

		// 2. Is re-authentication required? max_age=0 always is, the OIDC equivalent of prompt=login, whatever the clock.
		var required = authTime is null
			|| request.HasPromptValue(OpenIddictConstants.PromptValues.Login)
			|| maxAge == 0
			|| (maxAge is { } age && now.ToUnixTimeSeconds() - authTime.Value > age);

		if (required && authTime is not null
			&& await IsSatisfiedByMarkerAsync(parameters, principal!, userId!.Value, markers, ledger,
				context.RequestAborted).ConfigureAwait(false))
			required = false;

		if (required)
		{
			// 3. prompt=none never shows a page.
			if (request.HasPromptValue(OpenIddictConstants.PromptValues.None))
				return Error(OpenIddictConstants.Errors.LoginRequired);

			// 4. Challenge, carrying a fresh marker for this transaction.
			ReauthMarker marker = new(new Guid(RandomNumberGenerator.GetBytes(16)), userId,
				AuthorizeTransaction.Hash(parameters), now + ReauthMarkers.Lifetime);
			var reentry = UriHelper.BuildRelative(context.Request.PathBase, ReauthMarkers.AuthorizePath,
				QueryString.Create([
					.. parameters.Where(static parameter =>
						!string.Equals(parameter.Key, AuthorizeTransaction.MarkerParameter, StringComparison.Ordinal)),
					new(AuthorizeTransaction.MarkerParameter, markers.Protect(marker))
				]));
			if (!string.Equals(ReturnUrls.Resolve(reentry, context.Request.PathBase), reentry, StringComparison.Ordinal))
				return Error(OpenIddictConstants.Errors.InvalidRequest);
			return Results.Challenge(new() { RedirectUri = reentry }, [IdentityConstants.ApplicationScheme]);
		}

		// 5. Consent and minting.
		var clientId = request.ClientId ??
			throw new InvalidOperationException("The validated authorize request carries no client_id.");
		var application = Invariant(
			await applications.Outcome.FindByClientIdAsync(clientId, context.RequestAborted).ConfigureAwait(false),
			$"No application could be found for the validated client_id '{clientId}'.");
		var consentType = Invariant(
			await applications.Outcome.GetConsentTypeAsync(application, context.RequestAborted).ConfigureAwait(false),
			$"The application for client_id '{clientId}' carries no consent type.");
		if (!string.Equals(consentType, OpenIddictConstants.ConsentTypes.Implicit, StringComparison.Ordinal))
			return Error(OpenIddictConstants.Errors.ConsentRequired);
		var applicationId = Invariant(
			await applications.Outcome.GetIdAsync(application, context.RequestAborted).ConfigureAwait(false),
			$"The application for client_id '{clientId}' carries no id.");

		var scopes = request.GetScopes();
		var minted = UserPrincipalFactory.Create(userId!.Value, authTime!.Value, stamp!, scopes);
		var authorization = Invariant(
			await authorizations.Outcome.CreateAsync(new()
			{
				ApplicationId = applicationId,
				CreationDate = now,
				Principal = minted,
				Scopes = [.. scopes],
				Status = OpenIddictConstants.Statuses.Valid,
				Subject = userId.Value.ToString(),
				Type = OpenIddictConstants.AuthorizationTypes.AdHoc
			}, context.RequestAborted).ConfigureAwait(false),
			"The ad-hoc authorization could not be created.");
		minted.SetAuthorizationId(Invariant(
			await authorizations.Outcome.GetIdAsync(authorization, context.RequestAborted).ConfigureAwait(false),
			"The ad-hoc authorization carries no id."));

		return Results.SignIn(minted, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
	}

	/// <summary>
	///     The cookie's user still exists, is not erased, and carries <paramref name="stamp" /> (final I1); a lockout is no
	///     reason. A missing or erased user answers <see langword="false" />; any other failure to read it is an invariant
	///     violation (500).
	/// </summary>
	static async Task<bool> IsCurrentAsync(UserManager<NorseUser> userManager, Guid userId, string stamp,
		CancellationToken cancellationToken)
	{
		var found = await userManager.Outcome.FindByIdAsync(userId.ToString(), cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed failed))
		{
			if (failed.Problem.Category is not (ErrorCategory.NotFound or ErrorCategory.Erased))
				throw new InvalidOperationException($"The cookie's user could not be read ({failed.Problem.Category}).");
			return false;
		}

		found.TryGetValue(out Success<NorseUser> user);
		return string.Equals(await userManager.GetSecurityStampAsync(user.Value).ConfigureAwait(false), stamp,
			StringComparison.Ordinal);
	}

	/// <summary>
	///     §5.2 step 4's re-entry conditions: exactly one marker, genuine and unexpired; this transaction's hash; the
	///     cookie bound to it; its user, or none; and its first burn in the ledger, last, so a failing condition never
	///     spends it. A lost acknowledgement reads as a replay.
	/// </summary>
	static async Task<bool> IsSatisfiedByMarkerAsync(List<KeyValuePair<string, StringValues>> parameters,
		ClaimsPrincipal principal, Guid userId, ReauthMarkers markers, IPasskeyChallengeLedger ledger,
		CancellationToken cancellationToken)
	{
		if (parameters.Where(static parameter =>
					string.Equals(parameter.Key, AuthorizeTransaction.MarkerParameter, StringComparison.Ordinal))
				.SelectMany(static parameter => parameter.Value).ToList() is not [{ } value]
			|| !markers.TryUnprotect(value, out var marker)
			|| !CryptographicOperations.FixedTimeEquals(marker.TransactionHash, AuthorizeTransaction.Hash(parameters))
			|| principal.FindAll(NorseSignInManager.ReauthClaimType).Take(2).ToList() is not [var binding]
			|| !string.Equals(binding.Value, marker.MarkerId.ToString("N"), StringComparison.Ordinal)
			|| (marker.UserId is { } markerUser && markerUser != userId))
			return false;

		return await ledger.TryConsumeAsync(Encoding.UTF8.GetBytes(LedgerPrefix + marker.MarkerId.ToString("N")),
			marker.ExpiresAt, cancellationToken).ConfigureAwait(false);
	}

	/// <summary>
	///     The cookie's <c>auth_time</c>: exactly one value, integral epoch seconds with no sign, fraction or exponent, and no
	///     further ahead than <see cref="ClockSkew" />. Anything else is <see langword="null" />: stale, never fresh.
	/// </summary>
	static long? ReadAuthTime(ClaimsPrincipal principal, DateTimeOffset now) =>
		principal.FindAll(NorseClaimTypes.AuthTime).Take(2).ToList() is [var claim]
		&& long.TryParse(claim.Value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
		&& seconds <= (now + ClockSkew).ToUnixTimeSeconds() ?
			seconds :
			null;

	/// <summary>
	///     Reads <c>max_age</c> raw: absent, or exactly one value of ASCII digits within <see cref="long" />. Anything else
	///     answers <see langword="false" />.
	/// </summary>
	static bool TryReadMaxAge(List<KeyValuePair<string, StringValues>> parameters, out long? maxAge)
	{
		maxAge = null;
		var values = parameters
			.Where(static parameter => string.Equals(parameter.Key, OpenIddictConstants.Parameters.MaxAge, StringComparison.Ordinal))
			.SelectMany(static parameter => parameter.Value)
			.ToList();
		if (values is [])
			return true;
		if (values is not [{ Length: > 0 } value] || !value.All(char.IsAsciiDigit)
			|| !long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds))
			return false;
		maxAge = seconds;
		return true;
	}

	/// <summary>
	///     A singular parameter that is repeated, or spelled in any other case than its exact name (I1). The framework merges a
	///     variant spelling and the exact one into one key, every value kept, under a spelling of its choosing (RC3 keeps the
	///     later one), so <c>max_age=0&amp;MAX_AGE=999</c> would otherwise read as no <c>max_age</c> at all. The merged key is all
	///     the parameter set preserves, which is enough: any variant spelling, beside or instead of the exact one, is refused.
	/// </summary>
	static bool IsAmbiguous(List<KeyValuePair<string, StringValues>> parameters) =>
		parameters.Any(static parameter =>
			_singular.TryGetValue(parameter.Key, out var exact)
			&& (parameter.Value.Count > 1 || !string.Equals(parameter.Key, exact, StringComparison.Ordinal)));

	/// <summary>A protocol error to the redirect URI, carrying <c>state</c>; no description and no URI (§5.7).</summary>
	static IResult Error(string error) =>
		Results.Forbid(new(new Dictionary<string, string?>
		{
			[OpenIddictServerAspNetCoreConstants.Properties.Error] = error
		}), [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);

	static T Invariant<T>(Outcome<T> outcome, string violation)
		where T : notnull =>
		outcome.Match(static value => value,
			problem => throw new InvalidOperationException($"{violation} ({problem.Category})"));
}
