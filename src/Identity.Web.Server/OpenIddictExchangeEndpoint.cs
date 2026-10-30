using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore; // OpenIddictServerAspNetCoreHelpers.GetOpenIddictServerRequest lives here, not OpenIddict.Server.AspNetCore.
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Components.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.OpenIddict;
using Norse.Primitives;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Norse.Identity.Web.Server;

/// <summary>
///     The token endpoint (Himinbjorg#49; 2026-10-29 OpenIddict spec §5.4), a passthrough for the three enabled grants.
///     OpenIddict has already authenticated the client, validated the presented grant (PKCE, redirect URI, the token's
///     entry and its authorization) and rejected every other grant type before this runs, so the grant-type switch's
///     fallthrough is an invariant violation, never a caller's error.
/// </summary>
/// <remarks>
///     <para>
///         <b>client_credentials</b> builds the principal OpenIddict does not invent on its own, and stamps a
///         <see cref="ClaimTypes.NameIdentifier" /> claim carrying the seeded <c>NorseOpenIddictApplication</c>'s own
///         <see cref="Guid" /> id — Midgard's <c>PrincipalAccessor.Seed</c> (the 2026-08-21 principal-at-the-door design)
///         unconditionally requires every principal reaching the mediator, browser or machine lane alike, to carry a
///         GUID-parseable <see cref="ClaimTypes.NameIdentifier" /> claim.
///     </para>
///     <para>
///         <b>authorization_code and refresh_token</b> carry their authentication in the grant (ruling 11): 1. read the
///         presented grant's validated principal from OpenIddict's own authentication of the request (the transaction's
///         <c>ProcessAuthenticationContext</c>, which authenticating the server scheme would answer) and its <c>sub</c>, <c>auth_time</c> and <c>norse_stamp</c>, exactly one each, and its authorization id, or answer <c>invalid_grant</c>;
///         2. reload the user and answer <c>invalid_grant</c>, ending the presented grant (<see cref="IGrantTermination" />),
///         when it is missing or erased, or carries a stamp other than the grant's; 3. mint from the grant
///         (<see cref="UserPrincipalFactory" />), never from a fresh read, so <c>auth_time</c> never advances through a
///         refresh. Errors are bare (§5.7): <see cref="SuppressErrorDetails{TContext}" /> strips OpenIddict's description
///         and URI from every token response.
///     </para>
///     <para>
///         <b>A lockout is not a withdrawal</b> (Buvy's lockout ruling): a failed-login lockout blocks credential sign-in
///         only, and anyone who knows the email can cause one, so it neither refuses nor ends an issued grant.
///         Administrative withdrawal is an explicit stamp change or a grant revocation, never inferred from a lockout date.
///     </para>
///     <para>
///         The reads that decide whether the grant ends ignore the request's cancellation, as <see cref="GrantTermination" />'s
///         first step does: a client hanging up must not keep its grant alive (M2).
///     </para>
/// </remarks>
static class OpenIddictExchangeEndpoint
{
	internal static async Task<IResult> Handle(HttpContext context, IOpenIddictApplicationManager manager,
		UserManager<NorseUser> userManager, IGrantTermination termination, NorseIdentityDbContext database)
	{
		var request = context.GetOpenIddictServerRequest() ??
			throw new InvalidOperationException("The OpenIddict request cannot be retrieved.");

		// Internal invariant, not a user-facing branch: a violation here means the flow-gating in AddServer() broke, not that a
		// caller sent a bad request.
		if (request.IsClientCredentialsGrantType())
			return await ClientCredentialsAsync(request, manager, context.RequestAborted).ConfigureAwait(false);
		if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
			return await GrantAsync(context, request, userManager, termination, database).ConfigureAwait(false);
		throw new InvalidOperationException($"{nameof(OpenIddictExchangeEndpoint)} only handles the three enabled grants (client_credentials, authorization_code, refresh_token), but received grant type '{request.GrantType}'.");
	}

	/// <summary>§5.4 steps 1–3 for a presented code or refresh token.</summary>
	static async Task<IResult> GrantAsync(HttpContext context, OpenIddictRequest request, UserManager<NorseUser> userManager,
		IGrantTermination termination, NorseIdentityDbContext database)
	{
		// 1. Read the grant: the principal OpenIddict validated for the presented code or refresh token, from its own
		// authentication of this request (what authenticating the server scheme would answer), never an ambient principal.
		var authentication = context.Features.Get<OpenIddictServerAspNetCoreFeature>()?.Transaction?
				.GetProperty<ProcessAuthenticationContext>(typeof(ProcessAuthenticationContext).FullName!) ??
			throw new InvalidOperationException("The token request carries no OpenIddict authentication.");
		var grant = (request.IsAuthorizationCodeGrantType() ?
				authentication.AuthorizationCodePrincipal :
				authentication.RefreshTokenPrincipal) ??
			throw new InvalidOperationException("The validated grant carries no principal.");
		if (Single(grant, OpenIddictConstants.Claims.Subject) is not { } subject || !Guid.TryParse(subject, out var userId)
			|| Single(grant, NorseClaimTypes.AuthTime) is not { } authTimeValue
			|| !long.TryParse(authTimeValue, NumberStyles.None, CultureInfo.InvariantCulture, out var authTime)
			|| Single(grant, UserPrincipalFactory.StampClaimType) is not { } stamp)
			return InvalidGrant();
		// Fail-closed: a grant with no authorization to mint on would be handed a fresh ad-hoc one, splitting the grant. Every
		// grant this server issues has one (§4.5), so this is an anomaly: refused, after the grant its token's row still
		// links ends, never skipped quietly.
		if (!Guid.TryParse(grant.GetAuthorizationId(), out var authorization))
		{
			await UnanchoredGrant.EndAsync(database, termination, grant.GetTokenId(), grant.GetAuthorizationId(),
				context.RequestAborted).ConfigureAwait(false);
			return InvalidGrant();
		}

		// 2. Check the user: only authorization facts are re-read, never the authentication.
		if (!await IsStillAuthorizedAsync(userManager, subject, stamp).ConfigureAwait(false))
		{
			await termination.EndAsync(authorization, context.RequestAborted).ConfigureAwait(false);
			return InvalidGrant();
		}

		// 3. Mint from the grant, on the grant's authorization.
		var minted = UserPrincipalFactory.Create(userId, authTime, stamp, grant.GetScopes());
		minted.SetAuthorizationId(grant.GetAuthorizationId());
		return Results.SignIn(minted, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
	}

	/// <summary>
	///     The user exists, is not erased, and still carries <paramref name="stamp" />; a lockout is no reason (see the
	///     remarks). A missing or erased user answers <see langword="false" />; any other failure to read it is an invariant
	///     violation (500), never a refusal of the grant. The read ignores the request's cancellation: it decides whether the
	///     grant ends.
	/// </summary>
	static async Task<bool> IsStillAuthorizedAsync(UserManager<NorseUser> userManager, string subject, string stamp)
	{
		var found = await userManager.Outcome.FindByIdAsync(subject, CancellationToken.None).ConfigureAwait(false);
		if (found.TryGetValue(out Failed failed))
		{
			if (failed.Problem.Category is not (ErrorCategory.NotFound or ErrorCategory.Erased))
				throw new InvalidOperationException($"The grant's user could not be read ({failed.Problem.Category}).");
			return false;
		}

		found.TryGetValue(out Success<NorseUser> user);

		return string.Equals(await userManager.GetSecurityStampAsync(user.Value).ConfigureAwait(false), stamp,
			StringComparison.Ordinal);
	}

	/// <summary>The one non-empty value of <paramref name="type" />, or <see langword="null" />.</summary>
	static string? Single(ClaimsPrincipal principal, string type) =>
		principal.FindAll(type).Take(2).ToList() is [{ Value.Length: > 0 } claim] ?
			claim.Value :
			null;

	/// <summary><c>invalid_grant</c>, nothing optional (§5.7).</summary>
	static IResult InvalidGrant() =>
		Results.Forbid(new(new Dictionary<string, string?>
		{
			[OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant
		}), [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);

	/// <summary>The machine lane (Himinbjorg#49): the principal for the already-authenticated client.</summary>
	static async Task<IResult> ClientCredentialsAsync(OpenIddictRequest request, IOpenIddictApplicationManager manager,
		CancellationToken cancellationToken)
	{
		var clientId = request.ClientId ??
			throw new InvalidOperationException("The authenticated request carries no client_id.");

		// OpenIddict has already authenticated this request against the seeded application (see class
		// doc), so a miss here is an invariant violation, not a user-facing "unknown client" branch: the
		// .Outcome view's failure folds to the endpoint's own contract, an unhandled 500.
		var application = Invariant(
			await manager.Outcome.FindByClientIdAsync(clientId, cancellationToken).ConfigureAwait(false),
			$"No application could be found for the already-authenticated client_id '{clientId}'.");
		var applicationId = Guid.Parse(Invariant(
			await manager.Outcome.GetIdAsync(application, cancellationToken).ConfigureAwait(false),
			$"The application for client_id '{clientId}' carries no id."));

		// OpenIddictConstants.Claims.Subject ("sub"), not ClaimTypes.NameIdentifier (a different, URI-shaped
		// BCL claim type) -- OpenIddict's token-generation pipeline reads the principal's subject specifically
		// by this claim type, verified by reflection against the installed 7.6.0 package during planning.
		ClaimsIdentity identity = new(
			OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
			OpenIddictConstants.Claims.Subject, ClaimTypes.Role);
		identity.AddClaim(new Claim(OpenIddictConstants.Claims.Subject, clientId).SetDestinations(
			OpenIddictConstants.Destinations.AccessToken));
		// Midgard's PrincipalAccessor.Seed backstop -- see class doc.
		identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, applicationId.ToString()).SetDestinations(
			OpenIddictConstants.Destinations.AccessToken));

		ClaimsPrincipal principal = new(identity);
		principal.SetAudiences(NorseAudiences.Facade);

		return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
	}

	static T Invariant<T>(Outcome<T> outcome, string violation)
		where T : notnull =>
		outcome.Match(static value => value,
			problem => throw new InvalidOperationException($"{violation} ({problem.Category})"));
}
