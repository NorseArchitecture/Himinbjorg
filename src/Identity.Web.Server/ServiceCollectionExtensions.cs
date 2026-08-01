using Microsoft.AspNetCore.Identity;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.PostgreSQL;

namespace Norse.Identity.Web.Server;

/// <summary>Composition-root wiring for Identity.Web.Server's gRPC authentication service.</summary>
public static class ServiceCollectionExtensions
{
	extension(IHostApplicationBuilder builder)
	{
		/// <summary>
		/// Registers <see cref="NorseIdentityDbContext"/> (via
		/// <see cref="Norse.Persistence.EntityFramework.NorseContextExtensions.AddNorseContext{TContext}"/>),
		/// ASP.NET Core Identity (with the <see cref="NorseSignInManager"/> override), the generated
		/// mediator handler/dispatch/validator registration (<c>AddNorseIdentityWebServerHandlers()</c>,
		/// emitted by Asgard's registration generator), and the code-first gRPC host with
		/// <see cref="IAuthenticationService"/>. Also subscribes the
		/// <c>Microsoft.AspNetCore.Identity</c> meter — ASP.NET Core Identity ships its own metrics,
		/// and Layer 0's <c>Norse.*</c> wildcard does not reach them.
		/// </summary>
		/// <param name="connectionStringName">The configuration key under <c>ConnectionStrings</c>.</param>
		/// <returns>The same <paramref name="builder"/> for chaining.</returns>
		public IHostApplicationBuilder AddNorseAuthenticationService(string connectionStringName)
		{
			builder.AddNorseContext<NorseIdentityDbContext>(NorsePostgresEfProvider.Instance, connectionStringName);
			builder.Services.AddNorseIdentity().AddSignInManager<NorseSignInManager>();
			builder.Services.AddNorseIdentityWebServerHandlers();

			// Registered here, not by the host: IEmailSender<NorseUser> is closed over an entity the
			// host has no business naming. A host wiring a real sender registers its own afterward and
			// wins the resolution.
			builder.Services.AddSingleton<IEmailSender<NorseUser>, IdentityNoOpEmailSender>();

			builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();

			// The realm that brings the dependency declares its telemetry: this project is the only
			// one on the platform referencing ASP.NET Core Identity, and its only consumer is
			// Web.Server — so the meter lands in exactly the container that should have it, with no
			// rule for anyone to remember.
			builder.Services.AddOpenTelemetry()
				.WithMetrics(static metrics => metrics.AddMeter("Microsoft.AspNetCore.Identity"));

			return builder;
		}
	}
}
