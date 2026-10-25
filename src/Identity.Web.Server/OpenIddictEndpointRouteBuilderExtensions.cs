namespace Norse.Identity.Web.Server;

/// <summary>Maps the OpenIddict token endpoint (Himinbjorg#49).</summary>
public static class OpenIddictEndpointRouteBuilderExtensions
{
	extension(IEndpointRouteBuilder endpoints)
	{
		/// <summary>Maps <c>/connect/token</c> onto <see cref="OpenIddictExchangeEndpoint" />, excluded from the OpenAPI document — OAuth token-endpoint machinery, not a partner-visible REST route.</summary>
		/// <returns>A convention builder for the mapped endpoint.</returns>
		public IEndpointConventionBuilder MapNorseOpenIddictEndpoints() =>
			endpoints.MapPost("/connect/token", OpenIddictExchangeEndpoint.Handle).ExcludeFromDescription();
	}
}
