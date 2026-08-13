using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     Norse platform ASP.NET Core Identity role entity, keyed by <see cref="Guid" />.
/// </summary>
public sealed class NorseRole : IdentityRole<Guid>, INorseEntity<NorseRole>, ITemporalEntity
{
	/// <summary>
	///     The role's claims.
	/// </summary>
	public ICollection<NorseRoleClaim> Claims { get; init; } = [];

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseRole> builder)
	{
		builder.ToTable("Roles");
		builder.Property(static r => r.ConcurrencyStamp).HasConversion(IdentityValueConverters.Stamp).IsRequired();
		builder.Property(static r => r.Name).IsRequired();
		builder.Property(static r => r.NormalizedName).IsRequired();
		builder
			.HasMany(static r => r.Claims)
			.WithOne(static c => c.Role)
			.HasForeignKey(static c => c.RoleId);
		builder.HasIndex(static r => r.NormalizedName).IsUnique();
	}
}
