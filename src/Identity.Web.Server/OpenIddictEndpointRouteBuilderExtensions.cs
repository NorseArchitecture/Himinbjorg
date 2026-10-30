using Norse.Identity.Web.Server.OpenIddict;

namespace Norse.Identity.Web.Server;

/// <summary>Maps the OpenIddict passthrough endpoints (Himinbjorg#49; 2026-10-29 OpenIddict spec §5.1).</summary>
public static class OpenIddictEndpointRouteBuilderExtensions
{
	extension(IEndpointRouteBuilder endpoints)
	{
		/// <summary>
		///     Maps <c>/connect/token</c> (POST) onto <see cref="OpenIddictExchangeEndpoint" /> and <c>/connect/authorize</c>
		///     (GET and POST, as OIDC permits) onto <see cref="OpenIddictAuthorizeEndpoint" />, excluded from the OpenAPI
		///     document — OAuth machinery, not partner-visible REST routes. <c>/connect/revoke</c> is OpenIddict's own and
		///     maps nothing.
		/// </summary>
		/// <returns>A convention builder over both endpoints.</returns>
		public IEndpointConventionBuilder MapNorseOpenIddictEndpoints()
		{
			var connect = endpoints.MapGroup(string.Empty);
			connect.MapPost("/connect/token", OpenIddictExchangeEndpoint.Handle);
			connect.MapMethods("/connect/authorize", [HttpMethods.Get, HttpMethods.Post], OpenIddictAuthorizeEndpoint.Handle);
			return connect.ExcludeFromDescription();
		}
	}
}
