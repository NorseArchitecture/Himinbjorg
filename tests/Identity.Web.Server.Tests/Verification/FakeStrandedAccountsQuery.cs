using Norse.Identity.Web.Server.Verification;

namespace Norse.Identity.Web.Server.Tests.Verification;

/// <summary>
///     A scripted <see cref="IStrandedAccountsQuery" /> that records its calls. Pages are served in order and the last
///     one repeats; every recheck goes through <see cref="Recheck" />, which by default finds every candidate still
///     stranded.
/// </summary>
sealed class FakeStrandedAccountsQuery : IStrandedAccountsQuery
{
	readonly List<int> _pageSizes = [];
	readonly List<Guid[]> _rechecked = [];
	StrandedPage[] _pages = [new([], null, true, true)];

	/// <summary>The recheck: the ids still stranded, or a fault to throw.</summary>
	public Func<IReadOnlyCollection<Guid>, ValueTask<Guid[]>> Recheck { get; set; } =
		static ids => ValueTask.FromResult(ids.ToArray());

	/// <summary>The page size of each <see cref="NextPageAsync" /> call, in order.</summary>
	public IReadOnlyList<int> PageSizes => _pageSizes;

	/// <summary>The ids of each <see cref="StillStrandedAsync" /> call, in order.</summary>
	public IReadOnlyList<Guid[]> Rechecked => _rechecked;

	/// <summary>Every call of either kind.</summary>
	public int Calls => _pageSizes.Count + _rechecked.Count;

	/// <summary>Serves <paramref name="pages" /> in order, the last one repeating.</summary>
	public void Serve(params StrandedPage[] pages) =>
		_pages = pages;

	/// <inheritdoc />
	public ValueTask<StrandedPage> NextPageAsync(int take, CancellationToken cancellationToken = default)
	{
		lock (_pageSizes)
		{
			_pageSizes.Add(take);
			return ValueTask.FromResult(_pages[Math.Min(_pageSizes.Count, _pages.Length) - 1]);
		}
	}

	/// <inheritdoc />
	public ValueTask<Guid[]> StillStrandedAsync(IReadOnlyCollection<Guid> ids, CancellationToken cancellationToken = default)
	{
		lock (_pageSizes)
			_rechecked.Add([.. ids]);
		return Recheck(ids);
	}
}
