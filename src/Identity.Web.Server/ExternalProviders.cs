using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Norse.Identity.Web.Server;

/// <summary>
///     The configured external sign-in providers: one typed OpenID Connect scheme per child of
///     <c>Identity:ExternalProviders</c>, signing into the external cookie with the authorization-code flow and PKCE.
///     Only the remote-failure handling is shared wiring (<see cref="ConfigureRemoteFailure" />); every scheme is the
///     framework's own <c>AddOpenIdConnect</c>, so its configure and post-configure options (the protected state
///     format, the backchannel and the configuration manager) are registered exactly as the framework registers them.
/// </summary>
public static partial class ExternalProviders
{
	/// <summary>The configuration section whose children name the providers.</summary>
	public const string SectionName = "Identity:ExternalProviders";

	/// <summary>
	///     The external ticket's <see cref="AuthenticationProperties.Items" /> key carrying the email the provider's id
	///     token vouched for (<see cref="RecordVerifiedEmail(JsonWebToken, AuthenticationProperties)" />). Properties are
	///     server-protected inside the external cookie, and no token claim can write them.
	/// </summary>
	internal const string VerifiedEmailItem = "Norse.Identity.VerifiedEmail";

	/// <summary>The one message a remote failure carries to the callback page; the provider's own text never does.</summary>
	internal const string RemoteFailureMessage = "The sign-in provider did not complete the sign-in.";

	/// <summary>The remote sign-in's failure when the id token names no single subject; never shown to the user.</summary>
	const string MissingSubjectMessage = "The id token did not carry exactly one subject.";

	/// <summary>
	///     The paths a provider's three remote paths may never take: the external-login routes, the callback page, and
	///     the framework's shared OpenID Connect defaults a host's own scheme answers on. A remote handler answers its
	///     paths ahead of routing, so a collision would shadow the route.
	/// </summary>
	static readonly string[] _reservedPaths =
	[
		.. ExternalLoginRoutes.All, "/Account/ExternalLogin", "/signin-oidc", "/signout-oidc", "/signout-callback-oidc"
	];

	/// <summary>
	///     A provider name is a scheme name, three URL path segments and a field of the pipe-joined two-factor challenge,
	///     so only a conservative set is accepted.
	/// </summary>
	[GeneratedRegex(@"^[A-Za-z0-9_-]+\z", RegexOptions.CultureInvariant)]
	private static partial Regex SafeProviderName();

	/// <param name="builder">The authentication builder to add the providers to.</param>
	extension(AuthenticationBuilder builder)
	{
		/// <summary>
		///     Adds one OpenID Connect scheme per child of <c>Identity:ExternalProviders</c>, named for the child's key and
		///     displayed under its required <c>DisplayName</c>. A missing <c>Authority</c> or <c>ClientId</c> fails options
		///     validation at startup; no section adds no scheme. A name is refused at registration unless it is drawn from
		///     <c>[A-Za-z0-9_-]</c> and its <c>/signin-</c>, <c>/signout-</c> and <c>/signout-callback-</c> paths collide with
		///     no other provider's, no external-login route and none of the framework's shared OpenID Connect defaults.
		///     The provider key and the email come only from the validated id token: no scheme calls the user-info
		///     endpoint, and no claim action maps onto the name identifier or the email.
		/// </summary>
		/// <param name="configuration">The configuration holding <c>Identity:ExternalProviders</c>.</param>
		/// <returns>The same <paramref name="builder" /> for chaining.</returns>
		/// <exception cref="InvalidOperationException">
		///     A provider has no <c>DisplayName</c>, an unsafe name, or a path that collides.
		/// </exception>
		public AuthenticationBuilder AddNorseExternalProviders(IConfiguration configuration)
		{
			ArgumentNullException.ThrowIfNull(builder);
			ArgumentNullException.ThrowIfNull(configuration);

			Dictionary<string, string> claimed = new(StringComparer.OrdinalIgnoreCase);
			foreach (var reserved in _reservedPaths)
				claimed[reserved] = "a reserved route";
			foreach (var provider in configuration.GetSection(SectionName).GetChildren())
			{
				var name = provider.Key;
				// Ruling 41: a scheme without a display name is hidden from every sign-in page, so a provider
				// configured without one would be registered and silently unreachable.
				var displayName = provider["DisplayName"];
				if (string.IsNullOrWhiteSpace(displayName))
					throw new InvalidOperationException($"{SectionName}:{name}:DisplayName is required.");
				if (!SafeProviderName().IsMatch(name))
					throw new InvalidOperationException(
						$"{SectionName}:{name} is not a valid provider name: use only letters, digits, '_' and '-'.");

#pragma warning disable CA1308 // A URL path segment, never compared as a normalized key.
				var segment = name.ToLowerInvariant();
#pragma warning restore CA1308
				PathString
					callbackPath = $"/signin-{segment}",
					remoteSignOutPath = $"/signout-{segment}",
					signedOutCallbackPath = $"/signout-callback-{segment}";
				foreach (var path in (ReadOnlySpan<PathString>)[callbackPath, remoteSignOutPath, signedOutCallbackPath])
				{
					if (claimed.TryGetValue(path.Value!, out var owner))
						throw new InvalidOperationException($"{SectionName}:{name}: {path} collides with {owner}.");
					claimed[path.Value!] = $"provider {name}";
				}

				builder.AddOpenIdConnect(name, displayName, options =>
				{
					options.SignInScheme = IdentityConstants.ExternalScheme;
					options.Authority = provider["Authority"];
					options.ClientId = provider["ClientId"];
					options.ClientSecret = provider["ClientSecret"];
					options.RequireHttpsMetadata = provider.GetValue("RequireHttpsMetadata", true);
					options.ResponseType = "code";
					options.UsePkce = true;
					options.Scope.Clear();
					options.Scope.Add("openid");
					options.Scope.Add("profile");
					options.Scope.Add("email");
					options.CallbackPath = callbackPath;
					// Per scheme, never the shared /signout-oidc defaults the first registered scheme would claim for all.
					options.RemoteSignOutPath = remoteSignOutPath;
					options.SignedOutCallbackPath = signedOutCallbackPath;
					options.MapInboundClaims = false;
					// The key and the email come only from the validated id token (OnTokenValidated): no user-info call,
					// and no claim action that could write either one.
					options.GetClaimsFromUserInfoEndpoint = false;
					options.ClaimActions.Remove("email");
					options.ClaimActions.Remove(ClaimTypes.Email);
					options.ClaimActions.Remove(ClaimTypes.NameIdentifier);
					options.Events.OnTokenValidated = OnTokenValidated;
					ConfigureRemoteFailure(options);

					// Judged here, before the framework's post-configure, which would otherwise throw its own
					// InvalidOperationException/ArgumentNullException at the first challenge rather than a validation
					// failure naming the setting.
					List<string> failures = [];
					if (string.IsNullOrEmpty(options.Authority))
						failures.Add($"{SectionName}:{name}:Authority is required.");
					if (string.IsNullOrEmpty(options.ClientId))
						failures.Add($"{SectionName}:{name}:ClientId is required.");
					if (failures.Count > 0)
						throw new OptionsValidationException(name, typeof(OpenIdConnectOptions), failures);
				});
				// Resolved while the host starts, so a misconfigured provider fails before serving.
				builder.Services.AddOptions<OpenIdConnectOptions>(name).ValidateOnStart();
			}

			return builder;
		}
	}

	/// <summary>
	///     The one production remote-failure handler (T3-18): it sends the browser to the callback page with a fixed
	///     message, never the provider's error text, and ends the remote request there.
	/// </summary>
	/// <param name="context">The remote failure.</param>
	/// <returns>A completed task.</returns>
	internal static Task RedirectRemoteFailure(RemoteFailureContext context)
	{
		ArgumentNullException.ThrowIfNull(context);
		context.Response.Redirect(UriHelper.BuildRelative(context.Request.PathBase, "/Account/ExternalLogin",
			QueryString.Create("RemoteError", RemoteFailureMessage)));
		context.HandleResponse();
		return Task.CompletedTask;
	}

	/// <summary>Points <paramref name="options" />' remote failures at <see cref="RedirectRemoteFailure" />: the only shared wiring.</summary>
	/// <param name="options">A remote scheme's options.</param>
	internal static void ConfigureRemoteFailure(RemoteAuthenticationOptions options)
	{
		ArgumentNullException.ThrowIfNull(options);
		// A scheme whose options do not create their events (a bare AddRemoteScheme) gets the base set here.
		options.Events ??= new();
		options.Events.OnRemoteFailure = RedirectRemoteFailure;
	}

	/// <summary>
	///     Decides both things the external ticket takes from the validated id token, never from the claim set: the
	///     vouched-for email (<see cref="RecordVerifiedEmail(JsonWebToken, AuthenticationProperties)" />) and the provider
	///     key (<see cref="BindProviderKey" />); a token without exactly one <c>sub</c> fails the remote sign-in, which
	///     <see cref="RedirectRemoteFailure" /> sends to the fixed remote error. The RC3 handler hands the event a
	///     <see cref="JwtSecurityToken" /> converted from the validated <see cref="JsonWebToken" />'s encoded token (its
	///     decrypted inner token when encrypted), so the same bytes are read back as a <see cref="JsonWebToken" />;
	///     nothing is re-validated.
	/// </summary>
	/// <param name="context">The validated token's context.</param>
	/// <returns>A completed task.</returns>
	internal static Task OnTokenValidated(TokenValidatedContext context)
	{
		ArgumentNullException.ThrowIfNull(context);
		var idToken = (context.SecurityToken?.InnerToken ?? context.SecurityToken) is { RawData.Length: > 0 } validated ?
			new JsonWebToken(validated.RawData) :
			null;

		if (context.Properties is { } properties)
		{
			if (idToken is null)
				properties.Items.Remove(VerifiedEmailItem);
			else
				RecordVerifiedEmail(idToken, properties);
		}

		if (idToken is null || context.Principal is not { } principal || !BindProviderKey(idToken, principal))
			context.Fail(MissingSubjectMessage);
		return Task.CompletedTask;
	}

	/// <summary>
	///     The one decision on a provider's email: <see cref="VerifiedEmailItem" /> carries the id token's
	///     <c>email</c> only when the token holds exactly one <c>email</c>, a non-empty string, and exactly one
	///     <c>email_verified</c> whose value reads <c>true</c> (any casing; a JSON boolean or string), both matched by
	///     ordinal claim name. Anything else removes the item, so a stale one never survives. The external principal's
	///     claims are never consulted: a claim name is the token issuer's to spell, and claim lookups ignore case.
	/// </summary>
	/// <param name="idToken">The validated id token.</param>
	/// <param name="properties">The ticket's properties, protected inside the external cookie.</param>
	internal static void RecordVerifiedEmail(JsonWebToken idToken, AuthenticationProperties properties)
	{
		ArgumentNullException.ThrowIfNull(idToken);
		ArgumentNullException.ThrowIfNull(properties);
		properties.Items.Remove(VerifiedEmailItem);

		Claim? email = null;
		Claim? verified = null;
		var emails = 0;
		var verifieds = 0;
		foreach (var claim in idToken.Claims)
		{
			if (string.Equals(claim.Type, "email", StringComparison.Ordinal))
			{
				email = claim;
				emails++;
			}
			else if (string.Equals(claim.Type, "email_verified", StringComparison.Ordinal))
			{
				verified = claim;
				verifieds++;
			}
		}

		if (emails == 1 && verifieds == 1
			&& email is { ValueType: ClaimValueTypes.String, Value.Length: > 0 }
			&& verified is { ValueType: ClaimValueTypes.String or ClaimValueTypes.Boolean }
			&& string.Equals(verified.Value, "true", StringComparison.OrdinalIgnoreCase))
			properties.Items[VerifiedEmailItem] = email.Value;
	}

	/// <summary>
	///     The one decision on the external login's provider key. RC3 <c>GetExternalLoginInfoAsync</c> keys the login on
	///     the principal's first <see cref="ClaimTypes.NameIdentifier" /> ahead of <c>sub</c>, and once the external
	///     cookie round-trips into plain identities that lookup ignores case, so a token claim spelled like it would
	///     name the login. Every claim of that type, in any casing, leaves every identity, and exactly one is added from
	///     the token's own <c>sub</c>, matched by ordinal claim name: exactly one, a non-empty string. Anything else adds
	///     none and answers false.
	/// </summary>
	/// <param name="idToken">The validated id token.</param>
	/// <param name="principal">The external principal built from it.</param>
	/// <returns>Whether the principal now carries the one provider key.</returns>
	internal static bool BindProviderKey(JsonWebToken idToken, ClaimsPrincipal principal)
	{
		ArgumentNullException.ThrowIfNull(idToken);
		ArgumentNullException.ThrowIfNull(principal);

		// By predicate, never FindAll(string): the handler's CaseSensitiveClaimsIdentity matches a type ordinally.
		var removed = true;
		foreach (var identity in principal.Identities)
			foreach (var forged in identity.FindAll(static claim =>
				string.Equals(claim.Type, ClaimTypes.NameIdentifier, StringComparison.OrdinalIgnoreCase)).ToList())
				removed &= identity.TryRemoveClaim(forged);

		Claim? subject = null;
		var subjects = 0;
		foreach (var claim in idToken.Claims)
			if (string.Equals(claim.Type, "sub", StringComparison.Ordinal))
			{
				subject = claim;
				subjects++;
			}

		if (!removed || subjects != 1 || subject is not { ValueType: ClaimValueTypes.String, Value.Length: > 0 }
			|| principal.Identities.FirstOrDefault() is not { } primary)
			return false;

		primary.AddClaim(new(ClaimTypes.NameIdentifier, subject.Value, ClaimValueTypes.String, subject.Issuer,
			subject.OriginalIssuer));
		return true;
	}
}
