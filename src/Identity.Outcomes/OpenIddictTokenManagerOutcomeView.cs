using Norse.Abstractions.Contracts;
using OpenIddict.Abstractions;

namespace Norse.Identity.Outcomes;

/// <summary>
///     <c>tokenManager.Outcome</c> (2026-10-24 explicit-writes spec §4.12; 2026-10-29 OpenIddict spec §5.5, §5.8): the stock
///     <see cref="IOpenIddictTokenManager" />, answering <see cref="Outcome{T}" /> through <see cref="IdentityOutcomeMap" />,
///     as <see cref="OpenIddictAuthorizationManagerOutcomeView" /> does. Each method keeps the name of the manager method it
///     wraps.
/// </summary>
/// <param name="manager">The manager this view wraps.</param>
public sealed class OpenIddictTokenManagerOutcomeView(IOpenIddictTokenManager manager)
{
	/// <summary>
	///     Wraps <see cref="IOpenIddictTokenManager.RevokeByAuthorizationIdAsync" />: <c>EndGrant</c>'s step 2, every token
	///     of one authorization revoked.
	/// </summary>
	/// <param name="identifier">The authorization's id.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	/// <returns>How many tokens were revoked.</returns>
	public ValueTask<Outcome<long>> RevokeByAuthorizationIdAsync(string identifier,
		CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () =>
			Outcome<long>.Ok(await manager.RevokeByAuthorizationIdAsync(identifier, cancellationToken).ConfigureAwait(false)));

	/// <summary>
	///     Wraps <see cref="IOpenIddictTokenManager.PruneAsync" />: the pruner's first step (2026-10-29 OpenIddict spec §5.6),
	///     every token created before <paramref name="threshold" /> that is expired, no longer valid, or under an authorization
	///     that is no longer valid.
	/// </summary>
	/// <param name="threshold">The creation date before which tokens are pruned.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	/// <returns>How many tokens were removed.</returns>
	public ValueTask<Outcome<long>> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () =>
			Outcome<long>.Ok(await manager.PruneAsync(threshold, cancellationToken).ConfigureAwait(false)));
}
