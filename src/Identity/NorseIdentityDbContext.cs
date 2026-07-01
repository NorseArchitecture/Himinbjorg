using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Norse.EntityFramework;

namespace Norse.Identity;

/// <summary>
/// Norse platform Identity <see cref="IdentityDbContext{TUser,TRole,TKey,TUserClaim,TUserRole,TUserLogin,TRoleClaim,TUserToken,TUserPasskey}"/>,
/// combining ASP.NET Core Identity and OpenIddict entity sets. Applies snake_case naming conventions
/// via <see cref="NorseDbContextOptionsExtensions.ApplyNorseConventions"/> since it cannot inherit
/// <see cref="NorseDbContext"/> directly.
/// </summary>
/// <param name="options">The options for this context.</param>
public sealed class NorseIdentityDbContext(DbContextOptions<NorseIdentityDbContext> options)
	: IdentityDbContext<
		NorseUser, NorseRole, Guid,
		NorseUserClaim, NorseUserRole, NorseUserLogin,
		NorseRoleClaim, NorseUserToken, NorseUserPasskey>(options), INorseDbContext
{
	/// <inheritdoc />
	protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
	{
		base.OnConfiguring(optionsBuilder);
		NorseDbContextOptionsExtensions.ApplyNorseConventions(optionsBuilder);
	}

	/// <inheritdoc />
	protected override void OnModelCreating(ModelBuilder builder)
	{
		base.OnModelCreating(builder);
		builder.UseOpenIddict<Guid>();
	}
}
