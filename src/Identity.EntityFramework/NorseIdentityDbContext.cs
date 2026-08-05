using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
// Microsoft.NET.Sdk, not Sdk.Web: DI's implicit using doesn't come for free here.
using Microsoft.Extensions.DependencyInjection;
using Norse.Persistence.EntityFramework;
using Norse.Primitives.Identifiers;

namespace Norse.Identity.EntityFramework;

/// <summary>
/// Norse platform Identity <see cref="IdentityDbContext{TUser,TRole,TKey,TUserClaim,TUserRole,TUserLogin,TRoleClaim,TUserToken,TUserPasskey}"/>,
/// combining ASP.NET Core Identity and OpenIddict entity sets. Naming conventions are applied by
/// whichever provider registration extension registers this context (see
/// <c>Norse.Persistence.EntityFramework.PostgreSQL.NorsePostgresContextExtensions</c> and its SQL Server
/// counterpart) — this class replicates <see cref="NorseDbContext"/>'s fixed-length and
/// <see cref="SequentialGuid"/> byte-order provider checks independently since it inherits
/// <c>IdentityDbContext</c>, not <see cref="NorseDbContext"/>.
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
	/// separately calling <c>Norse.Identity.Web.Server</c>'s <c>AddNorseIdentity()</c> (e.g. the migrations
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
		// Norse.Persistence.EntityFramework.FixedLengthAttribute's remarks.
		var isSqlServer = Database.ProviderName == NorseDbContextOptionsExtensions.SqlServerProviderName;
		NorseModelConventions.Apply(configurationBuilder,
			applyFixedLength: isSqlServer,
			sequentialGuidOrder: isSqlServer ? GuidByteOrder.SqlServer : GuidByteOrder.Rfc9562);
	}

	/// <inheritdoc />
	protected override void OnModelCreating(ModelBuilder builder)
	{
		base.OnModelCreating(builder);
		builder.UseOpenIddict<
			NorseOpenIddictApplication, NorseOpenIddictAuthorization,
			NorseOpenIddictScope, NorseOpenIddictToken, Guid>();
		builder.ApplyNorseConfigurations();

		// PII primitives seam (2026-08-03 spec §4.5): no struct-typed IPiiScalar<TSelf> property exists
		// on this schema yet -- IdentityUser<Guid>'s own [ProtectedPersonalData] properties (UserName,
		// Email, PhoneNumber) already ride ASP.NET Core Identity's built-in IPersonalDataProtector
		// conversion via ProtectPersonalData=true (see IdentityBuilderExtensions.AddNorseIdentity), which
		// is a different, narrower mechanism than the platform's PII scalar seam. The call site for
		// Norse.Persistence.EntityFramework.PiiProtectionModelExtensions.ProtectPiiScalars(builder,
		// protector) lands here, right after ApplyNorseConfigurations, the day this schema's first
		// struct-typed PII property (an EncryptedString-shaped value object) is added -- not before.

		// Filter differs by provider: SQL Server needs an explicit filtered index since the column is
		// nullable now (payload columns darken on erasure, they don't null -- but the lookup hash
		// legitimately can be absent pre-hash or post-erasure); Postgres's NULLS DISTINCT default
		// already treats multiple NULLs as non-colliding, so no filter is needed there.
		// Temporal system-versioning (spec §4.3) is deferred to a future effort -- IsTemporal() composed
		// with SplitToTable() on the same entity built a valid model but crashed SQL Server's migrations
		// SQL generator (NullReferenceException escaping the split table's inherited, incorrectly-null
		// period-column identifiers) at DDL-generation time. Recorded with a fold-in trigger in
		// ../Glitnir/docs/Platform/plans/2026-08-03-pii-primitives-identity-erasure-seam.md.
		var isSqlServer = Database.ProviderName == NorseDbContextOptionsExtensions.SqlServerProviderName;
		builder.Entity<NorseUser>(entity =>
		{
			entity.HasIndex(u => u.NormalizedUserName)
				.IsUnique()
				.HasFilter(isSqlServer ? "[NormalizedUserName] IS NOT NULL" : null);
		});
	}
}
