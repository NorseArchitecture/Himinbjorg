using Norse.Abstractions.Contracts;
using OpenIddict.Abstractions;

namespace Norse.Identity.Outcomes;

/// <summary>
///     <c>authorizationManager.Outcome</c> (2026-10-24 explicit-writes spec §4.12; 2026-10-29 OpenIddict spec §5.8): the
///     stock <see cref="IOpenIddictAuthorizationManager" />, answering <see cref="Outcome{T}" /> through
///     <see cref="IdentityOutcomeMap" />, as <see cref="OpenIddictApplicationManagerOutcomeView" /> does. A
///     <see langword="null" /> answer is <see cref="ErrorCategory.NotFound" />. Each method keeps the name of the manager
///     method it wraps.
/// </summary>
/// <param name="manager">The manager this view wraps.</param>
public sealed class OpenIddictAuthorizationManagerOutcomeView(IOpenIddictAuthorizationManager manager)
{
	/// <summary>
	///     Wraps <see cref="IOpenIddictAuthorizationManager.CreateAsync(OpenIddictAuthorizationDescriptor, CancellationToken)" />:
	///     the authorize endpoint's one ad-hoc authorization per request.
	/// </summary>
	/// <param name="descriptor">The authorization to create.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	public ValueTask<Outcome<object>> CreateAsync(OpenIddictAuthorizationDescriptor descriptor,
		CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () =>
			Outcome<object>.Ok(await manager.CreateAsync(descriptor, cancellationToken).ConfigureAwait(false)));

	/// <summary>Wraps <see cref="IOpenIddictAuthorizationManager.GetIdAsync" />.</summary>
	/// <param name="authorization">The authorization.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	public ValueTask<Outcome<string>> GetIdAsync(object authorization, CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () =>
			await manager.GetIdAsync(authorization, cancellationToken).ConfigureAwait(false) is { } id ?
				Outcome<string>.Ok(id) :
				Outcome<string>.Err(ErrorCategory.NotFound));

	/// <summary>
	///     Wraps <see cref="IOpenIddictAuthorizationManager.PruneAsync" />: the pruner's last step (2026-10-29 OpenIddict spec
	///     §5.6), every authorization created before <paramref name="threshold" /> that is ad-hoc or no longer valid and has no
	///     token attached.
	/// </summary>
	/// <param name="threshold">The creation date before which authorizations are pruned.</param>
	/// <param name="cancellationToken">Propagated to the manager.</param>
	/// <returns>How many authorizations were removed.</returns>
	public ValueTask<Outcome<long>> PruneAsync(DateTimeOffset threshold, CancellationToken cancellationToken = default) =>
		IdentityOutcomeMap.GuardAsync(async () =>
			Outcome<long>.Ok(await manager.PruneAsync(threshold, cancellationToken).ConfigureAwait(false)));
}
