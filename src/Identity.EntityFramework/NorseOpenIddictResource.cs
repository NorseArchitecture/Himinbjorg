using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;
using OpenIddict.EntityFrameworkCore.Models;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     Norse wrapper over OpenIddict 8's EF Core resource entity, keyed by <see cref="Guid" />. Temporal: a resource
///     is part of the durable authorization record, like applications and scopes.
/// </summary>
public sealed class NorseOpenIddictResource
	: OpenIddictEntityFrameworkCoreResource<Guid>, INorseEntity<NorseOpenIddictResource>, ITemporalEntity
{
	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseOpenIddictResource> builder)
	{
		builder.ToTable("Resources");
		builder.Property(static r => r.Description).HasMaxLength(1000);
		builder.Property(static r => r.DisplayName).HasMaxLength(200);

		// JSON-string value converters OpenIddict 8 leaves unbounded by omission (verified against openiddict-core
		// 8.0.0-preview.4) -- genuinely unbounded, not merely unconfigured.
		builder.Property(static r => r.Descriptions).HasMaxLength(-1);
		builder.Property(static r => r.DisplayNames).HasMaxLength(-1);
		builder.Property(static r => r.Properties).HasMaxLength(-1);
	}
}
