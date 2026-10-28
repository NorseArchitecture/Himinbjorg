using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     A named, persisted keyset traversal position (T3-28), shared by every replica: the stranded-account
///     verification walks every account by id from <see cref="LastId" /> and advances it by compare-and-set on
///     <see cref="Version" />, so the cursor only moves forward within a traversal. Written only through explicit
///     statements, never tracked. Deliberately non-temporal: a runtime position, rewritten every advance, with no
///     history question.
/// </summary>
public sealed record VerificationCursor : NorseEntityBase<VerificationCursor>, INorseEntity<VerificationCursor>
{
	/// <summary>The traversal's name; the key.</summary>
	[MaxLength(64)]
	public required string Name { get; init; }

	/// <summary>The last id visited, or <see langword="null" /> at the start of the traversal.</summary>
	public Guid? LastId { get; init; }

	/// <summary>The compare-and-set token: 0 when the row is created, one more on every advance.</summary>
	public long Version { get; init; }

	/// <summary>When the cursor was last written.</summary>
	public required DateTimeOffset UpdatedAt { get; init; }

	/// <summary>Configures the EF entity mapping.</summary>
	public static void Configure(EntityTypeBuilder<VerificationCursor> builder)
	{
		builder.ToTable("VerificationCursors");
		builder.HasKey(static c => c.Name);
	}
}
