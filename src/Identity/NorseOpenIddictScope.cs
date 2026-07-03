using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.EntityFramework;
using OpenIddict.EntityFrameworkCore.Models;

namespace Norse.Identity;

/// <summary>
/// Norse wrapper over OpenIddict's EF Core scope entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseOpenIddictScope
	: OpenIddictEntityFrameworkCoreScope<Guid>, INorseEntity<NorseOpenIddictScope>
{
	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseOpenIddictScope> builder)
	{
		builder.Property(s => s.Description).HasMaxLength(1000);
		builder.Property(s => s.DisplayName).HasMaxLength(200);
	}
}
