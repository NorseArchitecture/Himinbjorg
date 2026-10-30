using Norse.Abstractions.Contracts;
using OpenIddict.Abstractions;

namespace Norse.Identity.Outcomes;

/// <summary>
///     <c>sessionManager.Outcome</c> (2026-10-29 OpenIddict spec §5.6, §5.8): the stock <see cref="IOpenIddictSessionManager" />,
///     answering <see cref="Outcome{T}" /> through <see cref="IdentityOutcomeMap" />, as
///     <see cref="OpenIddictTokenManagerOutcomeView" /> does. Each method keeps the name of the manager method it wraps.
/// </summary>
/// <param name="manager">The manager this view wraps.</param>
public sealed class OpenIddictSessionManagerOutcomeView(IOpenIddictSessionManager manager)
{
	/// <summary>
	///     Wraps <see cref="IOpenIddictSessionManager.PruneAsync" />: the pruner's second step, every session created before
	///     <paramref name="threshold" /> that is no longer valid and has no token attached, which is why tokens are pruned
	///     first.
	/// </summary>
	/// <param name="threshold">The creation date before which sessions are pruned.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	/// <returns>How many sessions were removed.</returns>
	public ValueTask<Outcome<long>> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () =>
			Outcome<long>.Ok(await manager.PruneAsync(threshold, cancellationToken).ConfigureAwait(false)));
}
