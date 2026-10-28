using System.Data.Common;
using System.Diagnostics.Metrics;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Store;
using Norse.Identity.Web.Server.Tests.Verification;
using Norse.Identity.Web.Server.Verification;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The stranded-account traversal (T3-28, Glitnir §2.2), once per provider: an ordered keyset walk over every
///     account by id, one <c>SampleSize + 1</c> lookahead read per page, so the last page wraps the cursor in the
///     same run, and a compare-and-set advance on the cursor's version, so no replica ever moves it backward.
/// </summary>
/// <remarks>
///     The fixture is shared and other suites seed accounts of their own, so a fact asserts only on the ids it seeded
///     (as <see cref="LastSignInMethodSuite" /> does), except where it counts the population or runs on a fresh
///     database of its own. Every fact first deletes the <c>"stranded-accounts"</c> cursor row. Test methods are
///     <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" /> records.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class StrandedAccountsSuite(IdentityFixture fixture)
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	const string Password = "Stranded-Accounts-9!";

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <summary>The current test's cancellation token.</summary>
	protected static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	/// <summary>
	///     Inserts a passwordless account with no logins by raw SQL: a <c>users</c> row and its
	///     <c>user_credentials</c> fragment, with every <c>NOT NULL</c> column filled and nothing protected.
	/// </summary>
	/// <param name="context">A context on the database to seed.</param>
	/// <param name="id">The account's id.</param>
	protected abstract Task SeedStrandedAsync(NorseIdentityDbContext context, Guid id);

	/// <summary>Deletes the <c>"stranded-accounts"</c> cursor row by raw SQL.</summary>
	/// <param name="context">A context on the fixture's database.</param>
	protected abstract Task DeleteCursorAsync(NorseIdentityDbContext context);

	/// <summary>Deletes one account by raw SQL; the cascade takes its fragment and children.</summary>
	/// <param name="context">A context on the fixture's database.</param>
	/// <param name="id">The account's id.</param>
	protected abstract Task DeleteUserAsync(NorseIdentityDbContext context, Guid id);

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_passwordless_account_without_logins_is_a_candidate()
	{
		fixture.SkipUnlessAvailable();
		var context = await ResetAsync();
		var id = Guid.NewGuid();
		await SeedStrandedAsync(context, id);
		try
		{
			(await TraverseAsync(context)).ShouldContain(id);
		}
		finally
		{
			await DeleteUserAsync(context, id);
		}
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_account_with_a_password_is_not_a_candidate()
	{
		fixture.SkipUnlessAvailable();
		var context = await ResetAsync();
		var id = await SeedCleanAsync();

		(await TraverseAsync(context)).ShouldNotContain(id);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_account_with_a_login_is_not_a_candidate()
	{
		fixture.SkipUnlessAvailable();
		var context = await ResetAsync();
		var id = await SeedStrandedAccountAsync();
		await LinkAsync(id);

		(await TraverseAsync(context)).ShouldNotContain(id);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Pages_follow_the_id_order_and_advance_the_cursor()
	{
		fixture.SkipUnlessAvailable();
		HashSet<Guid> seeded = [];
		for (var i = 0; i < 7; i++)
			seeded.Add(await SeedStrandedAccountAsync());
		var context = await ResetAsync();
		var ordered = await OrderedIdsAsync(context);
		StrandedAccountsQuery query = new(context, TimeProvider.System);

		for (var page = 0; page < 3; page++)
		{
			var window = ordered.Skip(page * 2).Take(2).ToList();
			var result = await query.NextPageAsync(2, Cancellation);

			result.Wrapped.ShouldBeFalse();
			result.Advanced.ShouldBeTrue();
			result.NextCursor.ShouldBe(window[^1]);
			// Disjoint and ascending: each page's candidates are exactly the stranded ids of its own window, in order.
			result.Candidates.ShouldBe([.. window.Where(result.Candidates.Contains)]);
			result.Candidates.ShouldBeSubsetOf(window);
			window.Where(seeded.Contains).ShouldBeSubsetOf(result.Candidates);
			var cursor = await CursorAsync(context);
			cursor.LastId.ShouldBe(window[^1]);
			cursor.Version.ShouldBe(page + 1);
		}
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Every_violating_account_is_reported_within_the_bound()
	{
		fixture.SkipUnlessAvailable();
		List<Guid> stranded = [], clean = [];
		for (var i = 0; i < 7; i++)
			stranded.Add(await SeedStrandedAccountAsync());
		for (var i = 0; i < 3; i++)
			clean.Add(await SeedCleanAsync());
		var context = await ResetAsync();
		var population = await context.Users.CountAsync(Cancellation);
		var runs = (population + 2) / 3 + 1;

		var critical = await DriveAsync(new() { SampleSize = 3, Interval = TimeSpan.FromMinutes(1) }, runs);

		foreach (var id in stranded)
			critical.ShouldContain(line => line.Contains(id.ToString()), $"stranded account {id} was not reported");
		foreach (var id in clean)
			critical.ShouldNotContain(line => line.Contains(id.ToString()));
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task The_cursor_wraps_to_the_start()
	{
		fixture.SkipUnlessAvailable();
		Guid first = new("00000000-0000-0000-0000-000000000001");
		var context = await ResetAsync();
		await DeleteUserAsync(context, first);
		await SeedStrandedAsync(context, first);
		try
		{
			var secondGreatest = await context.Users.OrderByDescending(static u => u.Id).Select(static u => u.Id).Skip(1)
				.FirstAsync(Cancellation);
			var now = DateTimeOffset.UtcNow;
			await ProviderStatements.EnsureVerificationCursorAsync(context, StrandedAccountsQuery.CursorName, now, Cancellation);
			(await ProviderStatements.AdvanceVerificationCursorAsync(context, StrandedAccountsQuery.CursorName, secondGreatest,
				0, now, Cancellation)).ShouldBe(1);
			StrandedAccountsQuery query = new(context, TimeProvider.System);

			// One row remains past the second-greatest id, fewer than SampleSize + 1: the last page, wrapped in this run.
			var last = await query.NextPageAsync(3, Cancellation);

			last.Wrapped.ShouldBeTrue();
			last.NextCursor.ShouldBeNull();
			last.Advanced.ShouldBeTrue();
			(await CursorAsync(context)).LastId.ShouldBeNull();

			(await query.NextPageAsync(3, Cancellation)).Candidates.ShouldContain(first);
		}
		finally
		{
			await DeleteUserAsync(context, first);
		}
	}

	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[InlineData(6, 2)]
	[InlineData(3, 1)]
	protected async Task An_exact_multiple_of_the_page_size_never_reads_an_empty_page(int accounts, int runs)
	{
		fixture.SkipUnlessAvailable();

		var visited = await WalkFreshAsync(accounts, runs, 3);

		visited.ShouldAllBe(static page => page.Length == 3);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_non_multiple_visits_every_account_within_the_ceiling()
	{
		fixture.SkipUnlessAvailable();

		var visited = await WalkFreshAsync(7, 3, 3);

		visited.Select(static page => page.Length).ShouldBe([3, 3, 1]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Interleaved_replicas_never_move_the_cursor_backward()
	{
		fixture.SkipUnlessAvailable();
		for (var i = 0; i < 6; i++)
			await SeedStrandedAccountAsync();
		await ResetAsync();
		AdvanceGate gate = new();
		await using var stalled = fixture.CreateContext(gate);
		var replicaA = new StrandedAccountsQuery(stalled, TimeProvider.System).NextPageAsync(2, Cancellation).AsTask();
		await gate.Reached.WaitAsync(TimeSpan.FromSeconds(30), Cancellation);

		var (context, _) = await fixture.CreateScopeAsync();
		StrandedAccountsQuery replicaB = new(context, TimeProvider.System);
		(await replicaB.NextPageAsync(2, Cancellation)).Advanced.ShouldBeTrue();
		var second = await replicaB.NextPageAsync(2, Cancellation);
		second.Advanced.ShouldBeTrue();
		gate.Release();
		var a = await replicaA;

		a.Advanced.ShouldBeFalse();
		var cursor = await CursorAsync(context);
		cursor.LastId.ShouldBe(second.NextCursor.ShouldNotBeNull());
		cursor.Version.ShouldBe(2);
	}

	// Both serial outcomes are valid (A advances to 1 then B to 2, or one advance loses), so this fact asserts
	// nothing about the version or the advance count: only that the first runs create one cursor between them.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Two_concurrent_first_runs_create_exactly_one_cursor()
	{
		fixture.SkipUnlessAvailable();

		// Several rounds, each on two fresh contexts, so the race is actually run, not just won.
		for (var round = 0; round < 5; round++)
		{
			var context = await ResetAsync();
			var (first, _) = await fixture.CreateScopeAsync();
			var (second, _) = await fixture.CreateScopeAsync();

			await Task.WhenAll(
				new StrandedAccountsQuery(first, TimeProvider.System).NextPageAsync(2, Cancellation).AsTask(),
				new StrandedAccountsQuery(second, TimeProvider.System).NextPageAsync(2, Cancellation).AsTask());

			(await context.Set<VerificationCursor>().CountAsync(static c => c.Name == StrandedAccountsQuery.CursorName,
				Cancellation)).ShouldBe(1);
		}
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Two_replicas_that_read_the_same_version_advance_exactly_once()
	{
		fixture.SkipUnlessAvailable();
		for (var i = 0; i < 3; i++)
			await SeedStrandedAccountAsync();
		var context = await ResetAsync();
		// The cursor exists before either replica starts, so both read (null, 0).
		await ProviderStatements.EnsureVerificationCursorAsync(context, StrandedAccountsQuery.CursorName, DateTimeOffset.UtcNow,
			Cancellation);
		AdvanceGate firstGate = new(), secondGate = new();
		await using var first = fixture.CreateContext(firstGate);
		await using var second = fixture.CreateContext(secondGate);
		var replicas = new[]
		{
			new StrandedAccountsQuery(first, TimeProvider.System).NextPageAsync(2, Cancellation).AsTask(),
			new StrandedAccountsQuery(second, TimeProvider.System).NextPageAsync(2, Cancellation).AsTask()
		};
		await Task.WhenAll(firstGate.Reached, secondGate.Reached).WaitAsync(TimeSpan.FromSeconds(30), Cancellation);

		firstGate.Release();
		secondGate.Release();
		var pages = await Task.WhenAll(replicas);

		pages.Count(static page => page.Advanced).ShouldBe(1);
		(await CursorAsync(context)).Version.ShouldBe(1);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task The_cursor_survives_a_restart()
	{
		fixture.SkipUnlessAvailable();
		for (var i = 0; i < 5; i++)
			await SeedStrandedAccountAsync();
		var context = await ResetAsync();
		var ordered = await OrderedIdsAsync(context);
		(await new StrandedAccountsQuery(context, TimeProvider.System).NextPageAsync(2, Cancellation)).NextCursor
			.ShouldBe(ordered[1]);

		// A restarted replica: a new scope, a new context, a new query, nothing carried over but the stored row.
		var (restarted, _) = await fixture.CreateScopeAsync();
		var resumed = await new StrandedAccountsQuery(restarted, TimeProvider.System).NextPageAsync(2, Cancellation);

		resumed.NextCursor.ShouldBe(ordered[3]);
		resumed.Candidates.ShouldBeSubsetOf(ordered.Skip(2).Take(2));
		(await CursorAsync(restarted)).Version.ShouldBe(2);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_still_stranded_recheck_drops_an_account_that_gained_a_login()
	{
		fixture.SkipUnlessAvailable();
		var id = await SeedStrandedAccountAsync();
		var (context, _) = await fixture.CreateScopeAsync();
		StrandedAccountsQuery query = new(context, TimeProvider.System);
		(await query.StillStrandedAsync([id], Cancellation)).ShouldBe([id]);

		await LinkAsync(id);

		(await query.StillStrandedAsync([id], Cancellation)).ShouldBeEmpty();
	}

	/// <summary>A context on the fixture's database, after deleting the cursor row.</summary>
	async Task<NorseIdentityDbContext> ResetAsync()
	{
		var (context, _) = await fixture.CreateScopeAsync();
		await DeleteCursorAsync(context);
		return context;
	}

	/// <summary>One whole traversal from the start: every candidate, up to and including the wrap.</summary>
	static async Task<List<Guid>> TraverseAsync(NorseIdentityDbContext context)
	{
		StrandedAccountsQuery query = new(context, TimeProvider.System);
		List<Guid> candidates = [];
		for (var page = 0; page < 1_000; page++)
		{
			var result = await query.NextPageAsync(100, Cancellation);
			candidates.AddRange(result.Candidates);
			if (result.Wrapped)
				return candidates;
		}

		throw new InvalidOperationException("The traversal never wrapped.");
	}

	/// <summary>
	///     Seeds <paramref name="accounts" /> stranded accounts on a fresh database, so the population is exactly the
	///     seed, then walks it for <paramref name="runs" /> pages of <paramref name="take" />: every account is visited,
	///     only the last page wraps, and no page is empty.
	/// </summary>
	async Task<List<Guid[]>> WalkFreshAsync(int accounts, int runs, int take)
	{
		await using var fresh = await fixture.CreateFreshDatabaseAsync();
		await using var context = fresh.CreateContext();
		List<Guid> seeded = [];
		for (var i = 0; i < accounts; i++)
		{
			var id = Guid.NewGuid();
			await SeedStrandedAsync(context, id);
			seeded.Add(id);
		}

		StrandedAccountsQuery query = new(context, TimeProvider.System);
		List<Guid[]> pages = [];
		for (var run = 1; run <= runs; run++)
		{
			var page = await query.NextPageAsync(take, Cancellation);
			page.Candidates.ShouldNotBeEmpty();
			page.Wrapped.ShouldBe(run == runs);
			page.Advanced.ShouldBeTrue();
			pages.Add(page.Candidates);
		}

		pages.SelectMany(static page => page).ShouldBe(seeded, ignoreOrder: true);
		return pages;
	}

	/// <summary>
	///     Drives the real service, with a fake clock and a fake logger, over the fixture's database for
	///     <paramref name="runs" /> runs, and returns its Critical lines.
	/// </summary>
	async Task<List<string>> DriveAsync(IdentityVerificationOptions options, int runs)
	{
		ServiceCollection services = new();
		services.AddMetrics();
		services.AddScoped(_ => fixture.CreateContext());
		services.AddScoped<IStrandedAccountsQuery>(static sp =>
			new StrandedAccountsQuery(sp.GetRequiredService<NorseIdentityDbContext>(), TimeProvider.System));
		await using var provider = services.BuildServiceProvider();
		FakeTimeProvider clock = new();
		FakeLogger<IdentityInvariantVerificationService> logger = new();
		using IdentityInvariantVerificationService service = new(provider.GetRequiredService<IServiceScopeFactory>(),
			Options.Create(options), logger, provider.GetRequiredService<IMeterFactory>(), clock);

		await service.StartAsync(Cancellation);
		await IdentityInvariantVerificationServiceTests.WaitForRunsAsync(logger.Collector, 1);
		for (var run = 2; run <= runs; run++)
		{
			clock.Advance(options.Interval);
			await IdentityInvariantVerificationServiceTests.WaitForRunsAsync(logger.Collector, run);
		}

		await service.StopAsync(Cancellation);
		var records = logger.Collector.GetSnapshot();
		records.ShouldNotContain(static record => record.Level == LogLevel.Error);
		return [.. records.Where(static record => record.Level == LogLevel.Critical).Select(static record => record.Message)];
	}

	/// <summary>Every account id, in the provider's own order (the database sorts).</summary>
	static Task<List<Guid>> OrderedIdsAsync(NorseIdentityDbContext context) =>
		context.Users.OrderBy(static u => u.Id).Select(static u => u.Id).ToListAsync(Cancellation);

	static async Task<VerificationCursor> CursorAsync(NorseIdentityDbContext context) =>
		await context.Set<VerificationCursor>().AsNoTracking()
			.SingleAsync(static c => c.Name == StrandedAccountsQuery.CursorName, Cancellation);

	/// <summary>A passwordless account with no logins, through the real manager.</summary>
	async Task<Guid> SeedStrandedAccountAsync() =>
		(await fixture.SeedUserAsync($"stranded-{Guid.NewGuid():N}@example.com")).Id;

	/// <summary>An account with a password, through the real manager.</summary>
	async Task<Guid> SeedCleanAsync()
	{
		var id = await SeedStrandedAccountAsync();
		var userManager = fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(id.ToString())).ShouldNotBeNull();
		(await userManager.AddPasswordAsync(user, Password)).Succeeded.ShouldBeTrue();
		return id;
	}

	async Task LinkAsync(Guid id)
	{
		var userManager = fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(id.ToString())).ShouldNotBeNull();
		(await userManager.AddLoginAsync(user, new UserLoginInfo("Stranded", $"stranded-{id:N}", "Stranded")))
			.Succeeded.ShouldBeTrue();
	}

	/// <summary>
	///     Holds the cursor advance (the query's only <c>UPDATE</c>) of the context it is attached to until released,
	///     after that context has read the cursor: the interleaving seam the replica facts need.
	/// </summary>
	sealed class AdvanceGate : DbCommandInterceptor
	{
		readonly TaskCompletionSource _reached = new(TaskCreationOptions.RunContinuationsAsynchronously);
		readonly TaskCompletionSource _released = new(TaskCreationOptions.RunContinuationsAsynchronously);

		/// <summary>Completes when the advance is about to be issued.</summary>
		public Task Reached => _reached.Task;

		/// <summary>Lets the held advance go.</summary>
		public void Release() =>
			_released.TrySetResult();

		/// <inheritdoc />
		public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
			CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
		{
			if (command.CommandText.TrimStart().StartsWith("UPDATE", StringComparison.OrdinalIgnoreCase))
			{
				_reached.TrySetResult();
				await _released.Task.WaitAsync(cancellationToken);
			}

			return result;
		}
	}
}
