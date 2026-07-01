using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
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
	/// <summary>
	/// Guarantees ASP.NET Core Identity's <c>Version3</c> schema shape (including the passkey table)
	/// regardless of caller. ASP.NET Core Identity decides schema shape by reading
	/// <c>IOptions&lt;IdentityOptions&gt;.Value.Stores.SchemaVersion</c> off
	/// <c>DbContextOptions.ApplicationServiceProvider</c> — a caller that registers this context without
	/// separately calling <see cref="IdentityBuilderExtensions.AddNorseIdentity"/> (e.g. the migrations
	/// service, which only needs the context to migrate, not the full Identity DI surface) would
	/// otherwise silently get <c>Version1</c> and miss the passkey table entirely.
	/// </summary>
	static readonly IServiceProvider _fallbackIdentityServices = new ServiceCollection()
		.Configure<IdentityOptions>(o => o.Stores.SchemaVersion = IdentitySchemaVersions.Version3)
		.BuildServiceProvider();

	/// <inheritdoc />
	protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
	{
		base.OnConfiguring(optionsBuilder);

		// Pooled hosts freeze options before OnConfiguring runs, and EF Core forbids OnConfiguring
		// from mutating frozen options at all -- both calls below mutate, so both must be skipped
		// together for a pooled context. A pooled host's real DI container is expected to apply
		// naming conventions itself at pool-template-build time (see AddNorsePostgresContext's
		// configureDbContextOptions parameter) and configure SchemaVersion correctly (see
		// AddNorseIdentity), so skipping both here is correct, not a loss, for that path.
		if (!optionsBuilder.Options.IsFrozen)
		{
			NorseDbContextOptionsExtensions.ApplyNorseConventions(optionsBuilder);
			optionsBuilder.UseApplicationServiceProvider(_fallbackIdentityServices);
		}
	}

	/// <inheritdoc />
	protected override void OnModelCreating(ModelBuilder builder)
	{
		base.OnModelCreating(builder);
		builder.UseOpenIddict<Guid>();
	}
}
