using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Norse.AuthN.Services;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity.Web.Server;

/// <summary>Composition-root wiring for Identity.Web.Server's gRPC authentication service.</summary>
public static class ServiceCollectionExtensions
{
	extension(IServiceCollection services)
	{
		/// <summary>
		/// Registers <see cref="NorseIdentityDbContext"/>, ASP.NET Core Identity (with the
		/// <see cref="NorseSignInManager"/> override), the generated mediator handler/dispatch/validator
		/// registration (<c>AddNorseIdentityWebServerHandlers()</c>, emitted by Asgard's registration
		/// generator), and the code-first gRPC host with <see cref="IAuthenticationService"/>.
		/// Also subscribes the <c>Microsoft.AspNetCore.Identity</c> meter — ASP.NET Core Identity
		/// ships its own metrics, and Layer 0's <c>Norse.*</c> wildcard does not reach them.
		/// </summary>
		public IServiceCollection AddNorseAuthenticationService(string connectionString)
		{
			services.AddDbContext<NorseIdentityDbContext>(o =>
			{
				o.UseNpgsql(connectionString);
				o.ApplyNorseConventions(NorseNameRewriters.LowerSnakeCase);
				o.ApplyNorseTrackingBehavior();
			});
			services.AddNorseIdentity().AddSignInManager<NorseSignInManager>();
			services.AddNorseIdentityWebServerHandlers();

			services.AddScoped<IAuthenticationService, AuthenticationService>();

			// The realm that brings the dependency declares its telemetry: this project is the only
			// one on the platform referencing ASP.NET Core Identity, and its only consumer is
			// Web.Server — so the meter lands in exactly the container that should have it, with no
			// rule for anyone to remember.
			services.AddOpenTelemetry()
				.WithMetrics(static metrics => metrics.AddMeter("Microsoft.AspNetCore.Identity"));

			return services;
		}
	}
}
