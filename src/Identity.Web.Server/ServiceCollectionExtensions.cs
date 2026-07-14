using Microsoft.EntityFrameworkCore;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components;
using Norse.EntityFramework;
using Norse.Infrastructure.Web.Server.Mediator.Grpc;
using ProtoBuf.Grpc.Server;

namespace Norse.Identity.Web.Server;

/// <summary>Composition-root wiring for Identity.Web.Server's gRPC authentication service.</summary>
public static class ServiceCollectionExtensions
{
	/// <summary>
	/// Registers <see cref="NorseIdentityDbContext"/>, ASP.NET Core Identity, the code-first gRPC host with
	/// <see cref="OutcomeServerInterceptor"/>, and the mediator handlers backing <see cref="IAuthenticationService"/>.
	/// </summary>
	public static IServiceCollection AddNorseAuthenticationService(this IServiceCollection services, string connectionString)
	{
		services.AddDbContext<NorseIdentityDbContext>(o =>
		{
			o.UseNpgsql(connectionString);
			NorseDbContextOptionsExtensions.ApplyNorseConventions(o);
		});
		services.AddNorseIdentity();
		services.AddHttpContextAccessor();
		services.AddCodeFirstGrpc(o => o.Interceptors.Add<OutcomeServerInterceptor>());

		services.AddScoped<LoginRequestValidator>();
		services.AddScoped<RegisterRequestValidator>();

		services.AddScoped<IRequestHandler<LoginRequest, Outcome<BoolResponse>>, LoginHandler>();
		services.AddScoped<IRequestHandler<RegisterRequest, Outcome<BoolResponse>>, RegisterHandler>();
		services.AddScoped<IRequestHandler<LogoutRequest, Outcome>, LogoutHandler>();

		services.AddScoped<IAuthenticationService, AuthenticationService>();

		return services;
	}
}
