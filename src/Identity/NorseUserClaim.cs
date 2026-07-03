using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.EntityFramework;

namespace Norse.Identity;

/// <summary>
/// Norse platform ASP.NET Core Identity user-claim entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseUserClaim : IdentityUserClaim<Guid>, INorseEntity<NorseUserClaim>
{
	/// <summary>
	/// The user this claim belongs to.
	/// </summary>
	public NorseUser? User { get; init; }

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseUserClaim> builder)
	{
		// ClaimType/ClaimValue are already bounded by IdentityDbContext's own base OnModelCreating.
		// Configure exists to satisfy RequireEntityConfigurationConvention and colocate for discoverability.
	}
}
