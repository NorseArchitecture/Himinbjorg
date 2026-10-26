using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     Norse platform ASP.NET Core Identity user-claim entity, keyed by <see cref="Guid" />.
/// </summary>
public sealed class NorseUserClaim : IdentityUserClaim<Guid>, INorseEntity<NorseUserClaim>, ITemporalEntity
{
	/// <summary>
	///     The user this claim belongs to.
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
		builder.Property(static c => c.ClaimType).HasMaxLength(256).IsRequired();
		// Brownfield exemption (2026-10-24 explicit-writes spec §14): hand-written .IsRequired() on a member whose
		// string? annotation belongs to IdentityUserClaim<Guid>. Required because the providers treat NULL in a
		// unique index differently, and claims are a set under the index below.
		builder.Property(static c => c.ClaimValue).HasMaxLength(-1).IsRequired();

		// Brownfield exemption (same spec §14): a shadow property, because a CLR member would change the drop-in
		// IdentityUserClaim<Guid> shape. ClaimValue is unbounded and can't be indexed directly, so the set's key
		// is a provider-computed, stored SHA-256 of it; the expression is provider-specific and is set in
		// NorseIdentityDbContext. Required: left nullable, EF filters the unique index, and SQL Server refuses a
		// filtered index on a computed column (PoC G6). An identical claim is never stored twice -- a deliberate
		// tightening of stock Identity. Spec §4.6.
		builder
			.Property<byte[]>(ClaimValueHash)
			.HasMaxLength(32)
			.IsRequired();
		builder
			.HasIndex(nameof(UserId), nameof(ClaimType), ClaimValueHash)
			.IsUnique();
	}

	/// <summary>The shadow property holding the stored SHA-256 of <see cref="IdentityUserClaim{TKey}.ClaimValue" />.</summary>
	public const string ClaimValueHash = nameof(ClaimValueHash);
}
