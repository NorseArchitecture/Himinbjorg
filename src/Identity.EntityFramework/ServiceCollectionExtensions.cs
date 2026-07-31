using Microsoft.Extensions.DependencyInjection;

namespace Norse.Identity.EntityFramework;

/// <summary>Composition-root wiring for the Identity/OpenIddict EF store.</summary>
public static class ServiceCollectionExtensions
{
	/// <param name="services">The service collection to configure.</param>
	extension(IServiceCollection services)
	{
		/// <summary>
		/// Registers OpenIddict's core services against <see cref="NorseIdentityDbContext"/>, with the
		/// four <c>NorseOpenIddict*</c> entities replacing OpenIddict's defaults. Lives here, not in
		/// <c>Norse.Identity.Web.Server</c>: the entities and the context it binds them to are this
		/// project's, and nothing about the binding needs an HTTP host.
		/// </summary>
		/// <returns>The <see cref="OpenIddictBuilder"/> for further chaining.</returns>
		public OpenIddictBuilder AddNorseOpenIddictCore() =>
			services
				.AddOpenIddict()
				.AddCore(o => o
					.UseEntityFrameworkCore()
					.UseDbContext<NorseIdentityDbContext>()
					.ReplaceDefaultEntities<
						NorseOpenIddictApplication, NorseOpenIddictAuthorization,
						NorseOpenIddictScope, NorseOpenIddictToken, Guid>());
	}
}
