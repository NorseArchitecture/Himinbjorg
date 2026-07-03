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

		// JSON-serialized collections/dictionaries OpenIddict itself leaves unbounded by omission
		// (verified against openiddict-core tag 7.5.0) -- genuinely unbounded, not merely unconfigured.
		builder.Property(a => a.DisplayNames).HasMaxLength(-1);
		builder.Property(a => a.JsonWebKeySet).HasMaxLength(-1);
		builder.Property(a => a.Permissions).HasMaxLength(-1);
		builder.Property(a => a.PostLogoutRedirectUris).HasMaxLength(-1);
		builder.Property(a => a.Properties).HasMaxLength(-1);
		builder.Property(a => a.RedirectUris).HasMaxLength(-1);
		builder.Property(a => a.Requirements).HasMaxLength(-1);
		builder.Property(a => a.Settings).HasMaxLength(-1);
	}
}
