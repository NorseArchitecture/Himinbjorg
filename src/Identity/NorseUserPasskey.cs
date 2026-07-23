using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity;

/// <summary>
/// Norse platform ASP.NET Core Identity passkey entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseUserPasskey : IdentityUserPasskey<Guid>, INorseEntity<NorseUserPasskey>
{
	/// <summary>
	/// The user this passkey belongs to.
	/// </summary>
	public NorseUser User { get; init; } = null!;

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseUserPasskey> builder)
	{
		builder.HasKey(p => p.CredentialId);
		builder.OwnsOne(p => p.Data, o => o.ToJson());
	}
}
