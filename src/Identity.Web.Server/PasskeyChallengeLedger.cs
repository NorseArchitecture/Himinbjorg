using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Store;

namespace Norse.Identity.Web.Server;

/// <summary>
///     The database <see cref="IPasskeyChallengeLedger" /> (T3-32): the <c>consumed_passkey_challenges</c> table in
///     <c>norse_identity</c>, so a one-shot holds across replicas and restarts. Scoped, on the request's own context:
///     each consumption prunes the rows expired past <see cref="SkewMargin" /> with one <c>DELETE</c>, then consumes with one set-based conditional
///     insert (<see cref="ProviderStatements.ConsumeChallengeAsync" />). Nothing is tracked, so a refused consumption
///     leaves the context exactly as it found it for the store's next write.
/// </summary>
/// <remarks>
///     Both statements run under the context's configured execution strategy, each on its own. A retried insert whose
///     first attempt landed reads as a replay: a lost acknowledgement fails the one-shot closed, never open.
/// </remarks>
/// <param name="context">The request's context.</param>
/// <param name="timeProvider">The clock expired consumptions are pruned by.</param>
sealed class PasskeyChallengeLedger(NorseIdentityDbContext context, TimeProvider timeProvider) : IPasskeyChallengeLedger
{
	/// <summary>
	///     How long past its expiry a consumption is kept: the protector judging a state's expiry may run on a replica
	///     whose clock trails this one, and a consumption pruned too early would let that replica accept a replay.
	/// </summary>
	internal static readonly TimeSpan SkewMargin = TimeSpan.FromMinutes(5);

	/// <inheritdoc />
	public async ValueTask<bool> TryConsumeAsync(ReadOnlyMemory<byte> stateBytes, DateTimeOffset expiresAt,
		CancellationToken cancellationToken = default)
	{
		var cutoff = timeProvider.GetUtcNow() - SkewMargin;
		await context.Set<ConsumedPasskeyChallenge>()
			.Where(r => r.ExpiresAt < cutoff)
			.ExecuteDeleteAsync(cancellationToken)
			.ConfigureAwait(false);
		return await ProviderStatements
			.ConsumeChallengeAsync(context, Hash(stateBytes), expiresAt.ToUniversalTime(), cancellationToken)
			.ConfigureAwait(false) is 1;
	}

	/// <summary>The ledger's key for <paramref name="stateBytes" />: its SHA-256, 32 bytes.</summary>
	/// <param name="stateBytes">The raw, unprotected state.</param>
	internal static byte[] Hash(ReadOnlyMemory<byte> stateBytes) =>
		SHA256.HashData(stateBytes.Span);
}
