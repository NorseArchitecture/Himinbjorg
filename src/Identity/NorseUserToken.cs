using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity;

/// <summary>
/// Norse platform ASP.NET Core Identity user-token entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseUserToken : IdentityUserToken<Guid>, INorseEntity<NorseUserToken>
{
	/// <summary>
	/// The user this token belongs to.
	/// </summary>
	public NorseUser User { get; init; } = null!;

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseUserToken> builder)
	{
		builder.Property(t => t.LoginProvider).HasMaxLength(128);
		builder.Property(t => t.Name).HasMaxLength(128);
		builder.Property(t => t.Value).HasMaxLength(-1);
	}
}
