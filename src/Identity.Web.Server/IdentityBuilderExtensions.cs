using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Components.Authorization;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.OpenIddict;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace Norse.Identity.Web.Server;

/// <summary>
///     Dependency-injection wiring for the Norse Identity stack.
/// </summary>
static class IdentityBuilderExtensions
{
	/// <param name="services">The service collection to configure.</param>
	extension(IServiceCollection services)
	{
		/// <summary>
		///     Registers ASP.NET Core Identity (with <see cref="NorseUserStore" /> and
		///     <see cref="NorseIdentityDbContext" /> as its EF stores) and OpenIddict's core services against the
		///     same context. Returns the <see cref="IdentityBuilder" />, not <see cref="IServiceCollection" /> — this
		///     project is shared with migration tooling and must not reference a <c>SignInManager</c> override; a
		///     caller that needs one chains <c>.AddSignInManager&lt;T&gt;()</c> on the returned builder itself.
		/// </summary>
		/// <remarks>
		///     Personal data protection is on: <see cref="NorsePersonalDataProtector" />,
		///     <see cref="NorseLookupProtector" />, and <see cref="NorseLookupProtectorKeyRing" /> are singletons
		///     over singleton seam dependencies, and <see cref="NorseUserManager" /> is the scope chokepoint that
		///     gives every write path the ambient crypto subject without Heimdall or any other caller needing to
		///     know the seam exists. Email is this platform's username, so <c>NormalizedEmail</c> and
		///     <c>NormalizedUserName</c> end up holding the same blind-index HMAC once both normalized values are
		///     updated -- that duplication is correct and expected, never a bug to "fix".
		/// </remarks>
		/// <param name="signingCertificate">
		///     The OpenIddict signing/encryption certificate — a single certificate serving both roles
		///     (spec §2.3). Callers own its lifetime; this method does not dispose it.
		/// </param>
		/// <param name="accessTokenLifetime">
		///     Overrides the access token lifetime, 10 minutes otherwise (spec §5.1). Omitted in production — exists so
		///     Task 11's expired-token test can mint a token that is already expired by the time it's used,
		///     without hand-constructing a JWT outside OpenIddict's own issuance path.
		/// </param>
		/// <returns>The <see cref="IdentityBuilder" /> for further chaining.</returns>
		public IdentityBuilder AddNorseIdentity(X509Certificate2 signingCertificate, TimeSpan? accessTokenLifetime = null)
		{
			services.Configure<IdentityOptions>(o =>
			{
				o.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
				o.Stores.ProtectPersonalData = true;
				// Email is the username, and both lookup hashes are NOT NULL on user_credentials, so a user
				// without an email is unrepresentable: Identity's own UserValidator refuses it as InvalidEmail
				// before any write, rather than the database refusing it as an exception (2026-10-24
				// explicit-writes spec §3.1).
				o.User.RequireUniqueEmail = true;
			});
			// T3-33: a passkey is possession plus inherence. Without user verification a PIN-less key is possession only,
			// so it is required, both in the options the browser gets and in the handler's own check of the
			// authenticator's UV flag. Pinned explicitly: RC3's default agrees today, but a default is not a ruling. A
			// PostConfigure, so a host's own later Configure cannot relax it.
			services.PostConfigure<IdentityPasskeyOptions>(o => o.UserVerificationRequirement = "required");
			services
				.AddSingleton<IPersonalDataProtector, NorsePersonalDataProtector>()
				.AddSingleton<ILookupProtector, NorseLookupProtector>()
				.AddSingleton<ILookupProtectorKeyRing, NorseLookupProtectorKeyRing>();

			var identityBuilder = services
				.AddIdentity<NorseUser, NorseRole>()
				.AddUserStore<NorseUserStore>()
				.AddUserManager<NorseUserManager>()
				.AddEntityFrameworkStores<NorseIdentityDbContext>()
				.AddDefaultTokenProviders()
				.AddClaimsPrincipalFactory<NorseUserClaimsPrincipalFactory>();

			// AddIdentity's default cookie name (".AspNetCore.Identity.Application") fingerprints the
			// stack to anyone inspecting cookies -- Norse.Identity carries the same information a
			// client needs (this is the identity cookie) without naming the framework underneath it.
			services.ConfigureApplicationCookie(options => options.Cookie.Name = "Norse.Identity");

			// ValidateOnStart on all three builders (spec §5.1): a broken OpenIddict configuration fails the host before it
			// serves, not at the first token request.
			services.AddNorseOpenIddictCore()
				.AddCore(static core => core.ValidateOnStart())
				.AddServer(o =>
				{
					// Spec §5.1: authorization code + PKCE (S256 only) and refresh for first-party public clients, beside the
					// machine lane's client_credentials; the authorize and token endpoints are Norse's (passthrough), revocation
					// is OpenIddict's own (v8 has no revocation passthrough: RFC 7009 handling under the grant boundary). Rolling
					// refresh tokens are OpenIddict's default and stay on, with zero reuse leeway.
					o.AllowClientCredentialsFlow()
						.AllowAuthorizationCodeFlow()
						.AllowRefreshTokenFlow()
						.RequireProofKeyForCodeExchange()
						// Relative without a leading slash, so OpenIddict resolves each under the live PathBase: it joins a relative
						// endpoint URI onto scheme://host/PathBase/ with new Uri(base, relative), and a leading slash would replace
						// the PathBase, so no request under a PathBase would ever match (decompiled preview.4, InferEndpointType).
						.SetAuthorizationEndpointUris("connect/authorize")
						.SetTokenEndpointUris("connect/token")
						.SetRevocationEndpointUris("connect/revoke")
						.RegisterScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess)
						.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(5))
						.SetAccessTokenLifetime(accessTokenLifetime ?? TimeSpan.FromMinutes(10))
						.SetIdentityTokenLifetime(TimeSpan.FromMinutes(10))
						.SetRefreshTokenLifetime(TimeSpan.FromDays(14))
						.SetRefreshTokenReuseLeeway(TimeSpan.Zero)
						// OpenIddict accepts plain and S256 by default and has no builder method that narrows the set.
						.Configure(static server =>
						{
							server.CodeChallengeMethods.Clear();
							server.CodeChallengeMethods.Add(OpenIddictConstants.CodeChallengeMethods.Sha256);
						})
						.DisableAccessTokenEncryption()
						.AddSigningCertificate(signingCertificate)
						.AddEncryptionCertificate(signingCertificate)
						.AddNorseGrantBoundary()
						.AddNorseErrorSuppression()
						.UseAspNetCore(a => a
							.EnableAuthorizationEndpointPassthrough()
							.EnableTokenEndpointPassthrough())
						.ValidateOnStart();
				})
				.AddValidation(o =>
				{
					// One validation scheme accepts both audiences, so every bearer-admitting policy pins its own (spec §7.4).
					o.UseLocalServer();
					o.AddAudiences(NorseAudiences.Facade, NorseAudiences.User);
					// The Authorization header is the only bearer channel: OAuth 2.1 forbids query-string tokens, and a form-body
					// token is the same leak on a POST.
					o.UseAspNetCore()
						.DisableAccessTokenExtractionFromQueryString()
						.DisableAccessTokenExtractionFromBodyForm();
					o.AddNorseErrorSuppression();
					o.ValidateOnStart();
				});

			// Spec §5.6: nothing else removes OpenIddict's runtime rows. The minimum age's floor is the refresh lifetime the
			// server above is configured with, read from its own options, never a copy of the constant.
			services.AddOptions<OpenIddictPruningOptions>()
				.BindConfiguration(OpenIddictPruningOptions.Section)
				.Validate(static pruning => pruning.Interval > TimeSpan.Zero,
					$"{OpenIddictPruningOptions.Section}:{nameof(OpenIddictPruningOptions.Interval)} must be positive.")
				.Validate(static pruning => pruning.Interval <= OpenIddictPruningOptions.MaxInterval,
					$"{OpenIddictPruningOptions.Section}:{nameof(OpenIddictPruningOptions.Interval)} must be at most {OpenIddictPruningOptions.MaxInterval}.")
				.Validate<IOptions<OpenIddictServerOptions>>(
					static (pruning, server) => server.Value.RefreshTokenLifetime is { } lifetime && pruning.MinimumAge >= lifetime,
					$"{OpenIddictPruningOptions.Section}:{nameof(OpenIddictPruningOptions.MinimumAge)} must be at least the OpenIddict server's refresh token lifetime, which must be finite.")
				.ValidateOnStart();
			services.TryAddSingleton(TimeProvider.System);
			services.AddHostedService<OpenIddictPruningService>();

			return identityBuilder;
		}
	}
}
