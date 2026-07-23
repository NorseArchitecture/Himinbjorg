using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity;

/// <summary>
/// Norse platform ASP.NET Core Identity user-claim entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseUserClaim : IdentityUserClaim<Guid>, INorseEntity<NorseUserClaim>
{
	/// <summary>
	/// The user this claim belongs to.
	/// </summary>
	public NorseUser User { get; init; } = null!;

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseUserClaim> builder)
	{
		builder.ToTable("UserClaims");
		// Contrary to Task 9's assumption, IdentityDbContext's own base OnModelCreating leaves
		// ClaimType/ClaimValue unbounded -- the RequireExplicitLengthConvention integration test
		// (Task 14) caught this. ClaimType is a URI-shaped identifier (bounded like
		// NorseUserLogin.ProviderDisplayName); ClaimValue is genuinely open-ended payload (unbounded
		// like NorseUserToken.Value).
		builder.Property(c => c.ClaimType).HasMaxLength(256);
		builder.Property(c => c.ClaimValue).HasMaxLength(-1);
	}
}
