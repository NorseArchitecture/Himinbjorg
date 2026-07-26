using FluentValidation;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components;
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
		/// <see cref="NorseSignInManager"/> override), the code-first gRPC host with
		/// <see cref="IAuthenticationService"/>.
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
			services.AddScoped<IValidator<LoginRequest>, LoginRequestValidator>();
			services.AddScoped<IValidator<RegisterRequest>, RegisterRequestValidator>();
			services.AddScoped<IValidator<LogoutRequest>, InlineValidator<LogoutRequest>>();

			services.AddScoped<IRequestHandler<LoginRequest, Outcome<BoolResponse>>, LoginHandler>();
			services.AddScoped<IRequestHandler<RegisterRequest, Outcome<BoolResponse>>, RegisterHandler>();
			services.AddScoped<IRequestHandler<LogoutRequest, Outcome<Unit>>, LogoutHandler>();

			services.AddScoped<IAuthenticationService, AuthenticationService>();

			return services;
		}
	}
}
