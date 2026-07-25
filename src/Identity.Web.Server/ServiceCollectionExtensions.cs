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
	/// <summary>
	/// Registers <see cref="NorseIdentityDbContext"/>, ASP.NET Core Identity (with the
	/// <see cref="NorseSignInManager"/> override), the code-first gRPC host with
	/// <see cref="IAuthenticationService"/>.
	/// </summary>
	public static IServiceCollection AddNorseAuthenticationService(this IServiceCollection services, string connectionString)
	{
		services.AddDbContext<NorseIdentityDbContext>(o =>
		{
			o.UseNpgsql(connectionString);
			o.ApplyNorseConventions();
		});
		services.AddNorseIdentity().AddSignInManager<NorseSignInManager>();
		services.AddScoped<FluentValidation.IValidator<LoginRequest>, LoginRequestValidator>();
		services.AddScoped<FluentValidation.IValidator<RegisterRequest>, RegisterRequestValidator>();
		services.AddScoped<FluentValidation.IValidator<LogoutRequest>, FluentValidation.InlineValidator<LogoutRequest>>();

		services.AddScoped<IRequestHandler<LoginRequest, Norse.Abstractions.Contracts.Outcome<BoolResponse>>, LoginHandler>();
		services.AddScoped<IRequestHandler<RegisterRequest, Norse.Abstractions.Contracts.Outcome<BoolResponse>>, RegisterHandler>();
		services.AddScoped<IRequestHandler<LogoutRequest, Norse.Abstractions.Contracts.Outcome<Unit>>, LogoutHandler>();

		services.AddScoped<IAuthenticationService, AuthenticationService>();

		return services;
	}
}
