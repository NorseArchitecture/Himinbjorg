using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
// Microsoft.NET.Sdk, not Sdk.Web: DI's implicit using doesn't come for free here.
using Microsoft.Extensions.DependencyInjection;
using Norse.Persistence.EntityFramework;
using Norse.Primitives.Identifiers;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     Norse platform Identity
///     <see cref="IdentityDbContext{TUser,TRole,TKey,TUserClaim,TUserRole,TUserLogin,TRoleClaim,TUserToken,TUserPasskey}" />
///     ,
///     combining ASP.NET Core Identity and OpenIddict entity sets. Naming conventions are applied by
///     whichever provider registration extension registers this context (see
///     <c>Norse.Persistence.EntityFramework.PostgreSQL.NorsePostgresContextExtensions</c> and its SQL Server
///     counterpart) — this class replicates <see cref="NorseDbContext" />'s fixed-length,
///     <see cref="SequentialGuid" /> byte-order, and temporal-realization plumbing independently since it
///     inherits <c>IdentityDbContext</c>, not <see cref="NorseDbContext" />.
/// </summary>
/// <param name="options">The options for this context.</param>
public sealed class NorseIdentityDbContext(DbContextOptions<NorseIdentityDbContext> options)
	: IdentityDbContext<
		NorseUser, NorseRole, Guid,
		NorseUserClaim, NorseUserRole, NorseUserLogin,
		NorseRoleClaim, NorseUserToken, NorseUserPasskey>(options), INorseDbContext
{
	/// <summary>
	///     Guarantees ASP.NET Core Identity's <c>Version3</c> schema shape (including the passkey table)
	///     regardless of caller. ASP.NET Core Identity decides schema shape by reading
	///     <c>IOptions&lt;IdentityOptions&gt;.Value.Stores.SchemaVersion</c> off
	///     <c>DbContextOptions.ApplicationServiceProvider</c> — a caller that registers this context without
	///     separately calling <c>Norse.Identity.Web.Server</c>'s <c>AddNorseIdentity()</c> (e.g. the migrations
	///     service, which only needs the context to migrate, not the full Identity DI surface) would
	///     otherwise silently get <c>Version1</c> and miss the passkey table entirely.
	/// </summary>
	static readonly IServiceProvider _fallbackIdentityServices = new ServiceCollection()
		.Configure<IdentityOptions>(o => o.Stores.SchemaVersion = IdentitySchemaVersions.Version3)
		.BuildServiceProvider();

	// Field initializer, not a captured primary-ctor parameter (CS9107), mirroring NorseDbContext: the
	// options are read once at construction, and the hook is the only fact this context needs from them.
	readonly Action<IConventionEntityType>? _temporalRealizationHook = options.GetTemporalRealizationHook();

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
			sequentialGuidOrder: isSqlServer ?
				GuidByteOrder.SqlServer :
				GuidByteOrder.Rfc9562,
			temporalRealizationHook: _temporalRealizationHook);
	}

	/// <inheritdoc />
	protected override void OnModelCreating(ModelBuilder builder)
	{
		base.OnModelCreating(builder);
		builder.UseOpenIddict<
			NorseOpenIddictApplication, NorseOpenIddictAuthorization, NorseOpenIddictResource,
			NorseOpenIddictScope, NorseOpenIddictSession, NorseOpenIddictToken, Guid>();
		builder.ApplyNorseConfigurations();

		// PII primitives seam (2026-08-03 spec §4.5): no struct-typed IPiiScalar<TSelf> property exists
		// on this schema yet -- IdentityUser<Guid>'s own [ProtectedPersonalData] properties (UserName,
		// Email, PhoneNumber) already ride ASP.NET Core Identity's built-in IPersonalDataProtector
		// conversion via ProtectPersonalData=true (see IdentityBuilderExtensions.AddNorseIdentity), which
		// is a different, narrower mechanism than the platform's PII scalar seam. The call site for
		// Norse.Persistence.EntityFramework.PiiProtectionModelExtensions.ProtectPiiScalars(builder,
		// protector) lands here, right after ApplyNorseConfigurations, the day this schema's first
		// struct-typed PII property (an EncryptedString-shaped value object) is added -- not before.

		// Temporal system-versioning: the eight entities carrying the durable identity and authorization
		// record declare ITemporalEntity, and Urðarbrunnr's chassis realizes it -- PostgreSQL in migration
		// SQL generation, SQL Server through the realization hook read off this context's options above.
		// NorseUser is the one split entity (the user_credentials fragment, Himinbjörg#47), and EF
		// can't compose IsTemporal() with SplitToTable() (dotnet/efcore#30366), so it declares
		// TemporalOnPrincipalTableOnly(): on SQL Server it is versioned engine-natively on users alone, not
		// EF-temporal; the other seven stay EF-native. Full design:
		// ../Glitnir/docs/Platform/specs/2026-08-04-temporal-tables-persistence-chassis-design.md and
		// ../Glitnir/docs/Himinbjorg/specs/2026-10-24-identity-explicit-writes-temporal-split-design.md §6.1.
		//
		// Two provider-specific expressions follow, here because only the context knows the provider. Email is
		// the username: CHECK (normalized_email = normalized_user_name) on the user_credentials fragment, with
		// both hashes NOT NULL (NorseUser.Configure), so the unique index on the user-name hash is email
		// uniqueness. EF can't declare a CHECK on a split fragment (an entity-level one lands on users, where the
		// columns no longer live), so it rides Urðarbrunnr's HasFragmentCheckConstraint, whose name is used
		// verbatim -- hence the provider-cased name as well as the provider-quoted SQL. Claims are a set:
		// claim_value_hash is a stored SHA-256 of claim_value -- PostgreSQL through
		// the chassis-owned IMMUTABLE norse_utf8_sha256 (convert_to is STABLE and refused inline), which
		// Urðarbrunnr's migrations generator emits ahead of user_claims; SQL Server cast to binary(32), since bare
		// HASHBYTES types the column varbinary(8000), past the index-key limit. EF emits no NOT NULL on a computed
		// column, so SQL Server infers nullability from the expression, and HASHBYTES reads as nullable: the
		// ISNULL(..., 0x) wrap is what makes the catalog report the column NOT NULL (ruled 2026-10-25, Task 4.13).
		// The fallback is unreachable, since ClaimValue is NOT NULL, and ISNULL takes its first argument's type, so
		// the column stays binary(32). The hash is provider-local and
		// never compared across providers. Writes to UserClaims need QUOTED_IDENTIFIER ON (SqlClient's default;
		// sqlcmd needs -I). ../Glitnir/docs/Himinbjorg/specs/2026-10-24-identity-explicit-writes-temporal-split-design.md
		// §3.1 and §4.6.
		var isSqlServer = Database.ProviderName == NorseDbContextOptionsExtensions.SqlServerProviderName;
		builder
			.Entity<NorseUser>()
			.SplitToTable(NorseUser.CredentialsTable, credentials => credentials.HasFragmentCheckConstraint(
				isSqlServer ?
					"CK_UserCredentials_EmailIsUserName" :
					"ck_user_credentials_email_is_user_name",
				isSqlServer ?
					"[NormalizedEmail] = [NormalizedUserName]" :
					"normalized_email = normalized_user_name"));
		builder
			.Entity<NorseUserClaim>()
			.Property<byte[]>(NorseUserClaim.ClaimValueHash)
			.HasComputedColumnSql(isSqlServer ?
					"ISNULL(CAST(HASHBYTES('SHA2_256', [ClaimValue]) AS binary(32)), 0x)" :
					"norse_utf8_sha256(claim_value)",
				stored: true);
	}
}
