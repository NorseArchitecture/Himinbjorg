namespace Norse.Identity.Web.Server.Verification;

/// <summary>
///     The stranded-account traversal over <c>norse_identity</c> (T3-28, Glitnir §2.2): an ordered keyset walk over
///     every account by id, shared by every replica through the <c>"stranded-accounts"</c> cursor.
/// </summary>
interface IStrandedAccountsQuery
{
	/// <summary>
	///     Reads the next page of <paramref name="take" /> accounts after the stored cursor and advances the cursor by
	///     compare-and-set, wrapping it to the start when this is the last page.
	/// </summary>
	/// <param name="take">The page size.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>The page's candidates and where the cursor went.</returns>
	ValueTask<StrandedPage> NextPageAsync(int take, CancellationToken cancellationToken = default);

	/// <summary>The second sighting: which of <paramref name="ids" /> are stranded now.</summary>
	/// <param name="ids">The previous run's candidates.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>The ids still stranded; an account deleted since is not.</returns>
	ValueTask<Guid[]> StillStrandedAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken = default);
}
