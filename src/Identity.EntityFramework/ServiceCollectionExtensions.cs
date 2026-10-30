using Microsoft.Extensions.DependencyInjection;

namespace Norse.Identity.EntityFramework;

/// <summary>Composition-root wiring for the Identity/OpenIddict EF store.</summary>
public static class ServiceCollectionExtensions
{
	/// <param name="services">The service collection to configure.</param>
	extension(IServiceCollection services)
	{
		/// <summary>
		///     Registers OpenIddict's core services against <see cref="NorseIdentityDbContext" />, with the
		///     six <c>NorseOpenIddict*</c> entities replacing OpenIddict's defaults, and the token, authorization
		///     and session stores replaced by the Norse adapters that keep the store link contract
		///     (2026-10-29 OpenIddict spec §4.5). Lives here, not in <c>Norse.Identity.Web.Server</c>: the
		///     entities and the context it binds them to are this project's, and nothing about the binding
		///     needs an HTTP host.
		/// </summary>
		/// <returns>The <see cref="OpenIddictBuilder" /> for further chaining.</returns>
		public OpenIddictBuilder AddNorseOpenIddictCore() =>
			services
				.AddOpenIddict()
				.AddCore(static core =>
				{
					core
						.UseEntityFrameworkCore()
						.UseDbContext<NorseIdentityDbContext>()
						.ReplaceDefaultEntities<
							NorseOpenIddictApplication, NorseOpenIddictAuthorization, NorseOpenIddictResource,
							NorseOpenIddictScope, NorseOpenIddictSession, NorseOpenIddictToken, Guid>();
					// After ReplaceDefaultEntities, which registers the stock stores: the last registration wins.
					core
						.ReplaceTokenStore<NorseOpenIddictToken, NorseOpenIddictTokenStore>()
						.ReplaceAuthorizationStore<NorseOpenIddictAuthorization, NorseOpenIddictAuthorizationStore>()
						.ReplaceSessionStore<NorseOpenIddictSession, NorseOpenIddictSessionStore>();
				});
	}
}
