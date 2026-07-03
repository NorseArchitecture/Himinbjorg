using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Norse.EntityFramework;

namespace Norse.Identity;

/// <summary>
/// Norse platform Identity <see cref="IdentityDbContext{TUser,TRole,TKey,TUserClaim,TUserRole,TUserLogin,TRoleClaim,TUserToken,TUserPasskey}"/>,
/// combining ASP.NET Core Identity and OpenIddict entity sets. Naming conventions are applied by
/// whichever provider registration extension registers this context (see
/// <c>Norse.EntityFramework.PostgreSQL.NorsePostgresContextExtensions</c> and its SQL Server
/// counterpart) — this class replicates <see cref="NorseDbContext"/>'s fixed-length provider check
/// independently since it inherits <c>IdentityDbContext</c>, not <see cref="NorseDbContext"/>.
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
		// from mutating frozen options at all -- the call below mutates, so it must be skipped for a
		// pooled context. A pooled host's real DI container is expected to configure SchemaVersion
		// correctly itself (see AddNorseIdentity), so skipping it here is correct, not a loss, for
		// that path.
		if (!optionsBuilder.Options.IsFrozen)
			optionsBuilder.UseApplicationServiceProvider(_fallbackIdentityServices);
	}

	/// <inheritdoc />
	protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
	{
		base.ConfigureConventions(configurationBuilder);

		// Fixed-length storage (char(n)/nchar(n)) only pays off on SQL Server -- see
		// Norse.EntityFramework.FixedLengthAttribute's remarks.
		NorseModelConventions.Apply(configurationBuilder,
			applyFixedLength: Database.ProviderName == NorseDbContextOptionsExtensions.SqlServerProviderName);
	}

	/// <inheritdoc />
	protected override void OnModelCreating(ModelBuilder builder)
	{
		base.OnModelCreating(builder);
		builder.HasDefaultSchema("identity");
		builder.UseOpenIddict<
			NorseOpenIddictApplication, NorseOpenIddictAuthorization,
			NorseOpenIddictScope, NorseOpenIddictToken, Guid>();
		builder.ApplyNorseConfigurations();
	}
}
