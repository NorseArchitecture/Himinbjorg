using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.EntityFramework;

namespace Norse.Identity;

/// <summary>
/// Norse platform ASP.NET Core Identity role-claim entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseRoleClaim : IdentityRoleClaim<Guid>, INorseEntity<NorseRoleClaim>
{
	/// <summary>
	/// The role this claim belongs to.
	/// </summary>
	public NorseRole? Role { get; init; }

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseRoleClaim> builder)
	{
		// ClaimType/ClaimValue are already bounded by IdentityDbContext's own base OnModelCreating.
		// Configure exists to satisfy RequireEntityConfigurationConvention and colocate for discoverability.
	}
}
