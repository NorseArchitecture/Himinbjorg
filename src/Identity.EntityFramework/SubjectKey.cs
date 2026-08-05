using System.Diagnostics.CodeAnalysis;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity.EntityFramework;

/// <summary>
/// The per-subject wrapped-DEK row (2026-08-03 PII spec §3.2): one wrap per subject regardless of
/// row count, one re-wrap point on rotation. The shred point is NOT this row — it is the wrapping
/// key in the platform key store; after destruction this row is permanent garbage, which the
/// envelope law permits. Deliberately non-temporal: a wrapped key has no history question.
/// </summary>
public sealed record SubjectKey : NorseEntityBase<SubjectKey>, INorseEntity<SubjectKey>
{
	/// <summary>The subject (user) identifier.</summary>
	public required Guid SubjectId { get; init; }
	/// <summary>The subject's DEK, wrapped under <see cref="WrappingKeyId"/>.</summary>
	[MaxLength(64)]
	[SuppressMessage("Design", "CA1819:Properties should not return arrays",
		Justification = "byte[] is the canonical CLR shape EF Core maps to a varbinary/bytea column; this is entity mapping, not a public collection-design surface.")]
	public required byte[] WrappedKey { get; init; }
	/// <summary>The wrapping-key reference in the platform key store.</summary>
	[MaxLength(128)]
	public required string WrappingKeyId { get; init; }
	/// <summary>When the wrap was minted.</summary>
	public required DateTimeOffset CreatedAt { get; init; }

	/// <summary>Configures the EF entity mapping.</summary>
	public static void Configure(EntityTypeBuilder<SubjectKey> builder)
	{
		builder.ToTable("SubjectKeys");
		builder.HasKey(k => k.SubjectId);
	}
}
