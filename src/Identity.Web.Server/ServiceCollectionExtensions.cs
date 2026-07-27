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
		/// </summary>
		public IServiceCollection AddNorseAuthenticationService(string connectionString)
		{
			services.AddDbContext<NorseIdentityDbContext>(o =>
			{
				o.UseNpgsql(connectionString);
				o.ApplyNorseConventions();
				o.ApplyNorseTrackingBehavior();
			});
			services.AddNorseIdentity().AddSignInManager<NorseSignInManager>();
			services.AddNorseIdentityWebServerHandlers();

			services.AddScoped<IAuthenticationService, AuthenticationService>();

			return services;
		}
	}
}
