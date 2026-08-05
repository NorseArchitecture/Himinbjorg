using Microsoft.AspNetCore.Identity;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server;

/// <summary>
/// Dependency-injection wiring for the Norse Identity stack.
/// </summary>
static class IdentityBuilderExtensions
{
	/// <param name="services">The service collection to configure.</param>
	extension(IServiceCollection services)
	{
		/// <summary>
		/// Registers ASP.NET Core Identity (with <see cref="NorseUserStore"/> and
		/// <see cref="NorseIdentityDbContext"/> as its EF stores) and OpenIddict's core services against the
		/// same context. Returns the <see cref="IdentityBuilder"/>, not <see cref="IServiceCollection"/> — this
		/// project is shared with migration tooling and must not reference a <c>SignInManager</c> override; a
		/// caller that needs one chains <c>.AddSignInManager&lt;T&gt;()</c> on the returned builder itself.
		/// </summary>
		/// <remarks>
		/// Personal data protection is on: <see cref="NorsePersonalDataProtector"/>,
		/// <see cref="NorseLookupProtector"/>, and <see cref="NorseLookupProtectorKeyRing"/> are singletons
		/// over singleton seam dependencies, and <see cref="NorseUserManager"/> is the scope chokepoint that
		/// gives every write path the ambient crypto subject without Heimdall or any other caller needing to
		/// know the seam exists. Email is this platform's username, so <c>NormalizedEmail</c> and
		/// <c>NormalizedUserName</c> end up holding the same blind-index HMAC once both normalized values are
		/// updated -- that duplication is correct and expected, never a bug to "fix".
		/// </remarks>
		/// <returns>The <see cref="IdentityBuilder"/> for further chaining.</returns>
		public IdentityBuilder AddNorseIdentity()
		{
			services.Configure<IdentityOptions>(o =>
			{
				o.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
				o.Stores.ProtectPersonalData = true;
			});
			services
				.AddSingleton<IPersonalDataProtector, NorsePersonalDataProtector>()
				.AddSingleton<ILookupProtector, NorseLookupProtector>()
				.AddSingleton<ILookupProtectorKeyRing, NorseLookupProtectorKeyRing>();

			var identityBuilder = services
				.AddIdentity<NorseUser, NorseRole>()
				.AddUserStore<NorseUserStore>()
				.AddUserManager<NorseUserManager>()
				.AddEntityFrameworkStores<NorseIdentityDbContext>()
				.AddDefaultTokenProviders();

			// AddIdentity's default cookie name (".AspNetCore.Identity.Application") fingerprints the
			// stack to anyone inspecting cookies -- Norse.Identity carries the same information a
			// client needs (this is the identity cookie) without naming the framework underneath it.
			services.ConfigureApplicationCookie(options => options.Cookie.Name = "Norse.Identity");

			services.AddNorseOpenIddictCore();

			return identityBuilder;
		}
	}
}
