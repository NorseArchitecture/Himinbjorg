using Microsoft.AspNetCore.Identity;

namespace Norse.Identity.Web.Server;

/// <summary>
/// Dependency-injection wiring for the Norse Identity stack.
/// </summary>
public static class IdentityBuilderExtensions
{
	/// <summary>
	/// Registers ASP.NET Core Identity (with <see cref="NorseUserStore"/> and
	/// <see cref="NorseIdentityDbContext"/> as its EF stores) and OpenIddict's core services against the
	/// same context. Returns the <see cref="IdentityBuilder"/>, not <see cref="IServiceCollection"/> — this
	/// project is shared with migration tooling and must not reference a <c>SignInManager</c> override; a
	/// caller that needs one chains <c>.AddSignInManager&lt;T&gt;()</c> on the returned builder itself.
	/// </summary>
	/// <param name="services">The service collection to configure.</param>
	/// <returns>The <see cref="IdentityBuilder"/> for further chaining.</returns>
	public static IdentityBuilder AddNorseIdentity(this IServiceCollection services)
	{
		services.Configure<IdentityOptions>(o => o.Stores.SchemaVersion = IdentitySchemaVersions.Version3);

		var identityBuilder = services
			.AddIdentity<NorseUser, NorseRole>()
			.AddUserStore<NorseUserStore>()
			.AddEntityFrameworkStores<NorseIdentityDbContext>()
			.AddDefaultTokenProviders();

		services
			.AddOpenIddict()
			.AddCore(o => o
				.UseEntityFrameworkCore()
				.UseDbContext<NorseIdentityDbContext>()
				.ReplaceDefaultEntities<
					NorseOpenIddictApplication, NorseOpenIddictAuthorization,
					NorseOpenIddictScope, NorseOpenIddictToken, Guid>());

		return identityBuilder;
	}
}
