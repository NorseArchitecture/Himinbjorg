using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     Norse platform ASP.NET Core Identity user entity, keyed by <see cref="Guid" />.
/// </summary>
public sealed class NorseUser : IdentityUser<Guid>, INorseEntity<NorseUser>, ITemporalEntity
{
	/// <summary>
	///     The user's claims.
	/// </summary>
	public ICollection<NorseUserClaim> Claims { get; init; } = [];

	/// <summary>
	///     The user's external logins.
	/// </summary>
	public ICollection<NorseUserLogin> Logins { get; init; } = [];

	/// <summary>
	///     The user's authentication tokens.
	/// </summary>
	public ICollection<NorseUserToken> Tokens { get; init; } = [];

	/// <summary>
	///     The user's passkeys.
	/// </summary>
	public ICollection<NorseUserPasskey> Passkeys { get; init; } = [];

	/// <summary>
	///     <c>UserManager{TUser}.NewSecurityStamp()</c> is <c>Base32.GenerateBase32()</c> — a
	///     hardcoded <c>string.Create(32, ...)</c> with no configuration option, always exactly 32
	///     characters (verified by decompiling Microsoft.Extensions.Identity.Core.dll directly).
	///     Overridden here purely to attach <see cref="FixedLengthAttribute" /> — the base
	///     <see cref="IdentityUser{TKey}.SecurityStamp" /> property can't carry an attribute Norse
	///     doesn't own.
	/// </summary>
	[FixedLength(32)]
	public override string? SecurityStamp { get; set; }

	/// <summary>
	///     The entity-splitting fragment holding the credential and lookup columns, named before the naming
	///     convention runs (<c>user_credentials</c> on PostgreSQL).
	/// </summary>
	public const string CredentialsTable = "UserCredentials";

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseUser> builder)
	{
		builder.ToTable("Users");
		builder
			.Property(static u => u.ConcurrencyStamp)
			.HasConversion(IdentityValueConverters.Stamp)
			.IsRequired();

		// UserManager.NewSecurityStamp() is Base32.GenerateBase32() -- always exactly 32 base32
		// characters, never Guid-shaped -- so this must stay a plain bounded string, not go through
		// IdentityValueConverters.Stamp (Guid.Parse would throw FormatException on every real stamp).
		// The value is genuinely fixed-length -- see the [FixedLength(32)] attribute on the
		// SecurityStamp override above -- but that's applied via the provider-gated
		// RequireExplicitLengthConvention (applyFixedLength), not a raw .IsFixedLength() Fluent call
		// here: SQL Server gets char(32)/nchar(32), while Postgres stays character varying(32), since
		// Postgres's own docs say character(n) has no storage/perf advantage over character varying(n)
		// on this engine (unlike SQL Server/MySQL) and is usually the slower of the two -- pure
		// downside, no upside, for Postgres.
		builder
			.Property(static u => u.SecurityStamp)
			.HasMaxLength(32)
			.IsRequired();

		builder
			.Property(static u => u.PasswordHash)
			.HasConversion(IdentityValueConverters.Hash)
			.HasMaxLength(128);

		// 20 fit a raw E.164 number; it doesn't fit the NorsePersonalDataProtector envelope
		// ("v1:{subjectId:D}:{base64}") ProtectPersonalData now writes here instead -- 256 mirrors
		// Email's own ASP.NET Core Identity convention bound (also unbounded-by-us, also ciphertext at
		// rest, also fits comfortably: worst case is "v1:" + a 36-char GUID + ":" + base64(12-byte
		// nonce + 16-byte E.164 plaintext + 16-byte tag), well under 100 characters).
		builder
			.Property(static u => u.PhoneNumber)
			.HasMaxLength(256);
		builder
			.Property(static u => u.UserName)
			.IsRequired();

		// Brownfield exemption (2026-10-24 explicit-writes spec §14): hand-written .IsRequired() on members
		// whose string? annotation belongs to IdentityUser<Guid>, not to us. Both lookup hashes are NOT NULL --
		// load-bearing for the fragment's CHECK (normalized_email = normalized_user_name), which an unknown
		// comparison would otherwise pass -- so Identity's own unique UserNameIndex on NormalizedUserName is
		// email uniqueness, unfiltered on both providers. Erasure is a hard delete now; nothing nulls them.
		// ../../../Glitnir/docs/Himinbjorg/specs/2026-10-24-identity-explicit-writes-temporal-split-design.md §3.1
		builder
			.Property(static u => u.NormalizedUserName)
			.IsRequired();
		builder
			.Property(static u => u.NormalizedEmail)
			.IsRequired();

		// The credential and lookup columns live in their own non-temporal fragment via entity splitting, so a
		// password change, stamp rotation, failed attempt or lockout never mints a users history row, and
		// erasure leaves none of them behind in history. LockoutEnabled is deliberately NOT split -- it's an
		// admin policy decision, which IS identity record. UserManager/SignInManager read and write the
		// properties unchanged; EF routes the columns. The fragment's FK to users cascades by default (PoC G3).
		// The CHECK lives in NorseIdentityDbContext, which knows the provider's column naming.
		// Same spec, §3.
		builder.SplitToTable(CredentialsTable, static credentials =>
		{
			credentials.Property(static u => u.PasswordHash);
			credentials.Property(static u => u.SecurityStamp);
			credentials.Property(static u => u.AccessFailedCount);
			credentials.Property(static u => u.LockoutEnd);
			credentials.Property(static u => u.NormalizedEmail);
			credentials.Property(static u => u.NormalizedUserName);
		});

		// EF can't scope SQL Server temporal system-versioning to one fragment of a split entity
		// (dotnet/efcore#26457; composing IsTemporal() with SplitToTable() NREs, #30366), so users opts
		// in to versioning its principal table only: on SQL Server the entity is deliberately not
		// EF-temporal, and Urðarbrunnr's migration seams emit engine-native system-versioning with
		// HIDDEN periods on users alone -- UserCredentials is never versioned. Cost, accepted for Identity
		// only: no TemporalAsOf/TemporalAll LINQ on NorseUser under SQL Server. A no-op on Postgres,
		// whose apparatus already versions the principal table only. The call site survives the day
		// upstream ships per-fragment control; only the opt-in's realization changes.
		// ../../../Glitnir/docs/Himinbjorg/specs/2026-10-24-identity-explicit-writes-temporal-split-design.md §6.1
		builder.TemporalOnPrincipalTableOnly();

		builder
			.HasMany(static u => u.Claims)
			.WithOne(static c => c.User)
			.HasForeignKey(static c => c.UserId);

		builder
			.HasMany(static u => u.Logins)
			.WithOne(static l => l.User)
			.HasForeignKey(static l => l.UserId);

		builder
			.HasMany(static u => u.Tokens)
			.WithOne(static t => t.User)
			.HasForeignKey(static t => t.UserId);

		builder
			.HasMany(static u => u.Passkeys)
			.WithOne(static p => p.User)
			.HasForeignKey(static p => p.UserId);

		builder.HasIndex(static u => u.NormalizedEmail);
	}
}
