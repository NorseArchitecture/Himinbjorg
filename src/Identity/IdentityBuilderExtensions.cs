using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Norse.Identity;

/// <summary>
/// Dependency-injection wiring for the Norse Identity stack.
/// </summary>
public static class IdentityBuilderExtensions
{
	/// <summary>
	/// Registers ASP.NET Core Identity (with <see cref="NorseUserStore"/> and
	/// <see cref="NorseIdentityDbContext"/> as its EF stores) and OpenIddict's core services against the
	/// same context.
	/// </summary>
	/// <param name="services">The service collection to configure.</param>
	/// <returns>The same <paramref name="services"/> for chaining.</returns>
	public static IServiceCollection AddNorseIdentity(this IServiceCollection services)
	{
		services
			.AddIdentity<NorseUser, NorseRole>()
			.AddUserStore<NorseUserStore>()
			.AddEntityFrameworkStores<NorseIdentityDbContext>()
			.AddDefaultTokenProviders();

		services
			.AddOpenIddict()
			.AddCore(o => o
				.UseEntityFrameworkCore()
				.UseDbContext<NorseIdentityDbContext>()
				.ReplaceDefaultEntities<Guid>());

		return services;
	}
}
