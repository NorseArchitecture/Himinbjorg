using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     Norse platform ASP.NET Core Identity user-role join entity, keyed by <see cref="Guid" />. The
///     explicit bridge entity for the User↔Role many-to-many — enables projection queries directly
///     against the join row, which EF Core's implicit skip-navigation many-to-many cannot do without
///     dropping into raw SQL.
/// </summary>
public sealed class NorseUserRole : IdentityUserRole<Guid>, INorseEntity<NorseUserRole>, ITemporalEntity
{
	/// <summary>
	///     The user.
	/// </summary>
	public NorseUser User { get; init; } = null!;

	/// <summary>
	///     The role.
	/// </summary>
	public NorseRole Role { get; init; } = null!;

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseUserRole> builder)
	{
		builder.ToTable("UserRoles");

		builder
			.HasOne(static ur => ur.User)
			.WithMany()
			.HasForeignKey(static ur => ur.UserId);

		builder
			.HasOne(static ur => ur.Role)
			.WithMany()
			.HasForeignKey(static ur => ur.RoleId);
	}
}
