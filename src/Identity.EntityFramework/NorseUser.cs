using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity.EntityFramework;

/// <summary>
/// Norse platform ASP.NET Core Identity user entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseUser : IdentityUser<Guid>, INorseEntity<NorseUser>
{
	/// <summary>
	/// The user's claims.
	/// </summary>
	public ICollection<NorseUserClaim> Claims { get; init; } = [];

	/// <summary>
	/// The user's external logins.
	/// </summary>
	public ICollection<NorseUserLogin> Logins { get; init; } = [];

	/// <summary>
	/// The user's authentication tokens.
	/// </summary>
	public ICollection<NorseUserToken> Tokens { get; init; } = [];

	/// <summary>
	/// The user's passkeys.
	/// </summary>
	public ICollection<NorseUserPasskey> Passkeys { get; init; } = [];

	/// <summary>
	/// <c>UserManager{TUser}.NewSecurityStamp()</c> is <c>Base32.GenerateBase32()</c> — a
	/// hardcoded <c>string.Create(32, ...)</c> with no configuration option, always exactly 32
	/// characters (verified by decompiling Microsoft.Extensions.Identity.Core.dll directly).
	/// Overridden here purely to attach <see cref="FixedLengthAttribute"/> — the base
	/// <see cref="IdentityUser{TKey}.SecurityStamp"/> property can't carry an attribute Norse
	/// doesn't own.
	/// </summary>
	[FixedLength(32)]
	public override string? SecurityStamp { get; set; }

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseUser> builder)
	{
		builder.ToTable("Users");
		builder.Property(u => u.ConcurrencyStamp).HasConversion(IdentityValueConverters.Stamp).IsRequired();
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
		builder.Property(u => u.SecurityStamp).HasMaxLength(32).IsRequired();
		builder.Property(u => u.PasswordHash).HasConversion(IdentityValueConverters.Hash).HasMaxLength(128);
		// 20 fit a raw E.164 number; it doesn't fit the NorsePersonalDataProtector envelope
		// ("v1:{subjectId:D}:{base64}") ProtectPersonalData now writes here instead -- 256 mirrors
		// Email's own ASP.NET Core Identity convention bound (also unbounded-by-us, also ciphertext at
		// rest, also fits comfortably: worst case is "v1:" + a 36-char GUID + ":" + base64(12-byte
		// nonce + 16-byte E.164 plaintext + 16-byte tag), well under 100 characters).
		builder.Property(u => u.PhoneNumber).HasMaxLength(256);
		builder.Property(u => u.UserName).IsRequired();

		builder.HasMany(u => u.Claims).WithOne(c => c.User).HasForeignKey(c => c.UserId).IsRequired();
		builder.HasMany(u => u.Logins).WithOne(l => l.User).HasForeignKey(l => l.UserId).IsRequired();
		builder.HasMany(u => u.Tokens).WithOne(t => t.User).HasForeignKey(t => t.UserId).IsRequired();
		builder.HasMany(u => u.Passkeys).WithOne(p => p.User).HasForeignKey(p => p.UserId).IsRequired();
		builder.HasIndex(u => u.NormalizedEmail);
	}
}
