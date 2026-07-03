using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.EntityFramework;
using OpenIddict.EntityFrameworkCore.Models;

namespace Norse.Identity;

/// <summary>
/// Norse wrapper over OpenIddict's EF Core application entity, keyed by <see cref="Guid"/>. Closes
/// two non-JSON columns OpenIddict leaves unbounded by omission (verified against
/// <c>openiddict-core</c> tag <c>7.5.0</c>).
/// </summary>
public sealed class NorseOpenIddictApplication
	: OpenIddictEntityFrameworkCoreApplication<Guid, NorseOpenIddictAuthorization, NorseOpenIddictToken>,
	  INorseEntity<NorseOpenIddictApplication>
{
	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseOpenIddictApplication> builder)
	{
		builder.Property(a => a.ClientSecret).HasMaxLength(-1);
		builder.Property(a => a.DisplayName).HasMaxLength(200);
	}
}
