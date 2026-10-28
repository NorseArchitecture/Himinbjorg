using System.Diagnostics.CodeAnalysis;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     One consumed one-shot state (T3-32): the SHA-256 of a sealed, time-limited state that has been redeemed, kept
///     until the state's own expiry, past which its protector refuses it anyway. Written only by one set-based
///     conditional insert, so a replay inserts nothing. Deliberately non-temporal: a nonce ledger is pruned on
///     expiry and has no history question.
/// </summary>
public sealed record ConsumedPasskeyChallenge : NorseEntityBase<ConsumedPasskeyChallenge>, INorseEntity<ConsumedPasskeyChallenge>
{
	/// <summary>The SHA-256 of the consumed state; the key.</summary>
	[FixedLength(32)]
	[SuppressMessage("Design", "CA1819:Properties should not return arrays",
		Justification =
			"byte[] is the canonical CLR shape EF Core maps to a binary/bytea column; this is entity mapping, not a public collection-design surface.")]
	public required byte[] ChallengeHash { get; init; } = [];

	/// <summary>The state's own expiry, past which the row is pruned.</summary>
	public required DateTimeOffset ExpiresAt { get; init; }

	/// <summary>Configures the EF entity mapping.</summary>
	public static void Configure(EntityTypeBuilder<ConsumedPasskeyChallenge> builder)
	{
		builder.ToTable("ConsumedPasskeyChallenges");
		builder.HasKey(static c => c.ChallengeHash);
		// The prune deletes by expiry before every consumption.
		builder.HasIndex(static c => c.ExpiresAt);
	}
}
