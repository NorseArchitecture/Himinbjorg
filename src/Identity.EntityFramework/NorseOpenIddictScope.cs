using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;
using OpenIddict.EntityFrameworkCore.Models;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     Norse wrapper over OpenIddict's EF Core scope entity, keyed by <see cref="Guid" />.
/// </summary>
public sealed class NorseOpenIddictScope
	: OpenIddictEntityFrameworkCoreScope<Guid>, INorseEntity<NorseOpenIddictScope>, ITemporalEntity
{
	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseOpenIddictScope> builder)
	{
		builder.ToTable("Scopes");
		builder.Property(static s => s.Description).HasMaxLength(1000);
		builder.Property(static s => s.DisplayName).HasMaxLength(200);

		// JSON-string value converters OpenIddict 8 leaves unbounded by omission (verified against openiddict-core
		// 8.0.0-preview.4) -- genuinely unbounded, not merely unconfigured. Resources is a string[] primitive
		// collection, never a string column, so it takes no length.
		builder.Property(static s => s.Descriptions).HasMaxLength(-1);
		builder.Property(static s => s.DisplayNames).HasMaxLength(-1);
		builder.Property(static s => s.Properties).HasMaxLength(-1);
	}
}
