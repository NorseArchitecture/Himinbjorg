using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Identity;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.Disclosure;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.PostgreSQL;

namespace Norse.Identity.Web.Server;

/// <summary>Composition-root wiring for Identity.Web.Server's gRPC authentication service.</summary>
public static class ServiceCollectionExtensions
{
	extension(IHostApplicationBuilder builder)
	{
		/// <summary>
		///     Registers <see cref="NorseIdentityDbContext" /> (via
		///     <see cref="Norse.Persistence.EntityFramework.NorseContextExtensions.AddNorseContext{TContext}" />),
		///     ASP.NET Core Identity (with the <see cref="NorseSignInManager" /> override), the generated
		///     mediator handler/dispatch/validator registration (<c>AddNorseIdentityWebServerHandlers()</c>,
		///     emitted by Asgard's registration generator), and the code-first gRPC host with
		///     <see cref="IAuthenticationService" />, <see cref="IIdentityService" /> (the disclosure
		///     surface -- self full, second-party masked, erased honest) and <see cref="IAccountService" /> (the
		///     self-service account surface). Also subscribes the
		///     <c>Microsoft.AspNetCore.Identity</c> meter — ASP.NET Core Identity ships its own metrics,
		///     and Layer 0's <c>Norse.*</c> wildcard does not reach them.
		/// </summary>
		/// <param name="connectionStringName">The configuration key under <c>ConnectionStrings</c>.</param>
		/// <param name="signingCertificate">The OpenIddict signing/encryption certificate (spec §2.3).</param>
		/// <param name="accessTokenLifetime">Overrides OpenIddict's default access token lifetime — see <see cref="IdentityBuilderExtensions.AddNorseIdentity" />.</param>
		/// <returns>The same <paramref name="builder" /> for chaining.</returns>
		public IHostApplicationBuilder AddNorseAuthenticationService(string connectionStringName,
			X509Certificate2 signingCertificate, TimeSpan? accessTokenLifetime = null) =>
			builder.AddNorseAuthenticationService(NorsePostgresEfProvider.Instance, connectionStringName,
				signingCertificate, accessTokenLifetime);

		/// <summary>
		///     The same composition over an explicit provider binding. Internal on purpose: production
		///     composes on Postgres through the public overload, and this seam exists so the SQL Server
		///     container fixture runs the identical graph rather than a hand-copied one.
		/// </summary>
		/// <param name="provider">The provider binding the context registers against.</param>
		/// <param name="connectionStringName">The configuration key under <c>ConnectionStrings</c>.</param>
		/// <param name="signingCertificate">The OpenIddict signing/encryption certificate (spec §2.3).</param>
		/// <param name="accessTokenLifetime">Overrides OpenIddict's default access token lifetime.</param>
		/// <returns>The same <paramref name="builder" /> for chaining.</returns>
		internal IHostApplicationBuilder AddNorseAuthenticationService(INorseEfProvider provider,
			string connectionStringName, X509Certificate2 signingCertificate, TimeSpan? accessTokenLifetime = null)
		{
			// Registered here, not by the host: IEmailSender<NorseUser> is closed over an entity the
			// host has no business naming. A host wiring a real sender registers its own afterward and
			// wins the resolution. Links and codes are credentials, and service defaults export logs:
			// only Development gets the logging sender, every other environment the silent no-op.
			builder.Services
				.AddNorseIdentityWebServerHandlers()
				.AddScoped<IAuthenticationService, AuthenticationService>()
				.AddScoped<IIdentityService, IdentityService>()
				.AddScoped<IAccountService, AccountService>()
				.AddScoped<ErasureService>()
				.AddScoped<DeferredCompletion>()
				.AddSingleton<IEmailSender<NorseUser>>(static sp =>
					sp.GetRequiredService<IHostEnvironment>().IsDevelopment()
						? ActivatorUtilities.CreateInstance<DevelopmentEmailSender>(sp)
						: new IdentityNoOpEmailSender())
				.AddNorseIdentity(signingCertificate, accessTokenLifetime)
				.AddSignInManager<NorseSignInManager>();

			// The realm that brings the dependency declares its telemetry: this project is the only
			// one on the platform referencing ASP.NET Core Identity, and its only consumer is
			// Web.Server — so the meter lands in exactly the container that should have it, with no
			// rule for anyone to remember.
			builder.Services
				.AddOpenTelemetry()
				.WithMetrics(static metrics => metrics.AddMeter("Microsoft.AspNetCore.Identity"));

			return builder.AddNorseContext<NorseIdentityDbContext>(provider, connectionStringName);
		}
	}
}
