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

		// JSON-serialized localized/collection columns OpenIddict itself leaves unbounded by omission
		// (verified against openiddict-core tag 7.5.0) -- genuinely unbounded, not merely unconfigured.
		builder.Property(static s => s.Descriptions).HasMaxLength(-1);
		builder.Property(static s => s.DisplayNames).HasMaxLength(-1);
		builder.Property(static s => s.Properties).HasMaxLength(-1);
		builder.Property(static s => s.Resources).HasMaxLength(-1);
	}
}
