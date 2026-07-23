using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity.Web.Server;

/// <summary>
/// Norse platform ASP.NET Core Identity role entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseRole : IdentityRole<Guid>, INorseEntity<NorseRole>
{
	/// <summary>
	/// The role's claims.
	/// </summary>
	public ICollection<NorseRoleClaim> Claims { get; init; } = [];

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseRole> builder)
	{
		builder.ToTable("Roles");
		builder.Property(r => r.ConcurrencyStamp).HasConversion(IdentityValueConverters.Stamp).IsRequired();
		builder.Property(r => r.Name).IsRequired();
		builder.Property(r => r.NormalizedName).IsRequired();
		builder.HasMany(r => r.Claims).WithOne(c => c.Role).HasForeignKey(c => c.RoleId).IsRequired();
		builder.HasIndex(r => r.NormalizedName).IsUnique();
	}
}
