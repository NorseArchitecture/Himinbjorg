namespace Norse.Identity.Web.Server;

/// <summary>Endpoint mapping for Identity.Web.Server's gRPC authentication service.</summary>
public static class WebApplicationExtensions
{
	/// <summary>Maps the code-first gRPC <see cref="AuthenticationService"/> endpoint onto <paramref name="app"/>.</summary>
	public static WebApplication MapNorseAuthenticationService(this WebApplication app)
	{
		app.MapGrpcService<AuthenticationService>();
		return app;
	}
}
