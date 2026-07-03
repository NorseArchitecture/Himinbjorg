using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.EntityFramework;

namespace Norse.Identity;

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

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseUser> builder)
	{
		builder.ToTable("users");
		builder.Property(u => u.ConcurrencyStamp).HasConversion(IdentityValueConverters.Stamp);
		// UserManager.NewSecurityStamp() is Base32.GenerateBase32() -- always exactly 32 base32
		// characters, never Guid-shaped -- so this must stay a plain bounded string, not go through
		// IdentityValueConverters.Stamp (Guid.Parse would throw FormatException on every real stamp).
		// Fixed-length, not "up to 32" -- the output length never varies.
		builder.Property(u => u.SecurityStamp).HasMaxLength(32).IsFixedLength();
		builder.Property(u => u.PasswordHash).HasConversion(IdentityValueConverters.Hash).HasMaxLength(128);
		builder.Property(u => u.PhoneNumber).HasMaxLength(20);

		builder.HasMany(u => u.Claims).WithOne(c => c.User).HasForeignKey(c => c.UserId).IsRequired();
		builder.HasMany(u => u.Logins).WithOne(l => l.User).HasForeignKey(l => l.UserId).IsRequired();
		builder.HasMany(u => u.Tokens).WithOne(t => t.User).HasForeignKey(t => t.UserId).IsRequired();
		builder.HasMany(u => u.Passkeys).WithOne(p => p.User).HasForeignKey(p => p.UserId).IsRequired();
		builder.HasIndex(u => u.NormalizedEmail).HasDatabaseName("ix_users_normalized_email");
		builder.HasIndex(u => u.NormalizedUserName).IsUnique().HasDatabaseName("ix_users_normalized_user_name");
	}
}
