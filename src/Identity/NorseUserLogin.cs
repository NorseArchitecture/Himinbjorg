using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity;

/// <summary>
/// Norse platform ASP.NET Core Identity external-login entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseUserLogin : IdentityUserLogin<Guid>, INorseEntity<NorseUserLogin>
{
	/// <summary>
	/// The user this external login belongs to.
	/// </summary>
	public NorseUser User { get; init; } = null!;

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseUserLogin> builder)
	{
		builder.ToTable("UserLogins");
		builder.Property(l => l.LoginProvider).HasMaxLength(128);
		builder.Property(l => l.ProviderKey).HasMaxLength(256);
		builder.Property(l => l.ProviderDisplayName).HasMaxLength(256);
	}
}
