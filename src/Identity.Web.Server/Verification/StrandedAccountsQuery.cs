using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Store;

namespace Norse.Identity.Web.Server.Verification;

/// <summary>
///     The stranded-account traversal over the host's <see cref="NorseIdentityDbContext" /> (T3-28, Glitnir §2.2),
///     through <see cref="ProviderStatements" /> only: nothing is tracked.
/// </summary>
/// <remarks>
///     Each page reads one row past the page size. More than <c>take</c> rows means a page follows, so the cursor
///     moves to the page's last id; at most <c>take</c> rows means this is the last page, so the cursor wraps to the
///     start in the same write, and a stable, nonempty population never spends a run on a wrap-only page. The
///     advance is a compare-and-set on the version this run read, so within a traversal the cursor only moves
///     forward, under any number of replicas. A retried advance whose first attempt landed reads as a lost one, which
///     costs a Debug line and nothing else.
/// </remarks>
/// <param name="context">The host's context.</param>
/// <param name="timeProvider">The clock that stamps the cursor's writes.</param>
sealed class StrandedAccountsQuery(NorseIdentityDbContext context, TimeProvider timeProvider) : IStrandedAccountsQuery
{
	/// <summary>The cursor's name in <c>verification_cursors</c>.</summary>
	public const string CursorName = "stranded-accounts";

	/// <inheritdoc />
	/// <remarks>
	///     The page's candidates are returned whether or not the advance won: an observation is valid either way, and
	///     the recheck and the report are idempotent (a recheck re-reads current state; reporting a confirmed id twice
	///     repeats a true Critical line, never a false one).
	/// </remarks>
	public async ValueTask<StrandedPage> NextPageAsync(int take, CancellationToken cancellationToken = default)
	{
		var now = timeProvider.GetUtcNow();
		await ProviderStatements.EnsureVerificationCursorAsync(context, CursorName, now, cancellationToken).ConfigureAwait(false);
		var (lastId, version) = await ProviderStatements.ReadVerificationCursorAsync(context, CursorName, cancellationToken)
			.ConfigureAwait(false);
		var rows = await ProviderStatements.ReadStrandedPageAsync(context, lastId, take + 1, cancellationToken)
			.ConfigureAwait(false);

		var wrapped = rows.Length <= take;
		var page = wrapped ? rows : rows[..take];
		Guid? next = wrapped ? null : page[^1].Id;
		var advanced = await ProviderStatements.AdvanceVerificationCursorAsync(context, CursorName, next, version, now,
			cancellationToken).ConfigureAwait(false) is 1;
		return new([.. page.Where(static row => row.Stranded).Select(static row => row.Id)], next, wrapped, advanced);
	}

	/// <inheritdoc />
	public async ValueTask<Guid[]> StillStrandedAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken = default) =>
		ids.Count is 0 ?
			[] :
			await ProviderStatements.ReadStillStrandedAsync(context, ids, cancellationToken).ConfigureAwait(false);
}
