using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;
using OpenIddict.EntityFrameworkCore.Models;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     Norse wrapper over OpenIddict's EF Core application entity, keyed by <see cref="Guid" />. Closes
///     two non-JSON columns OpenIddict leaves unbounded by omission (verified against
///     <c>openiddict-core</c> <c>8.0.0-preview.4</c>).
/// </summary>
public sealed class NorseOpenIddictApplication
	: OpenIddictEntityFrameworkCoreApplication<Guid, NorseOpenIddictAuthorization, NorseOpenIddictSession,
		NorseOpenIddictToken>,
		INorseEntity<NorseOpenIddictApplication>, ITemporalEntity
{
	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseOpenIddictApplication> builder)
	{
		builder.ToTable("Applications");
		builder.Property(static a => a.ClientSecret).HasMaxLength(-1);
		builder.Property(static a => a.DisplayName).HasMaxLength(200);

		// OpenIddict 8 maps the dictionaries and the key set through JSON-string value converters it leaves
		// unbounded by omission (verified against openiddict-core 8.0.0-preview.4) -- genuinely unbounded, not
		// merely unconfigured. The string[] members (Permissions, PostLogoutRedirectUris, RedirectUris,
		// Requirements) are primitive collections, never string columns, so they take no length.
		builder.Property(static a => a.DisplayNames).HasMaxLength(-1);
		builder.Property(static a => a.JsonWebKeySet).HasMaxLength(-1);
		builder.Property(static a => a.Properties).HasMaxLength(-1);
		builder.Property(static a => a.Settings).HasMaxLength(-1);
	}
}
