using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The consumed-challenge ledger (T3-32), once per provider: a state is consumed by one set-based conditional
///     insert, so the first consumption succeeds and every replay, sequential or concurrent, fails; an expired
///     consumption is pruned by the next one; and a refused consumption leaves its context exactly as it found it.
/// </summary>
/// <remarks>
///     Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///     records: xUnit discovers them on each <see langword="sealed" /> provider class.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class ConsumedPasskeyChallengeSuite(IdentityFixture fixture)
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	// Starts at the wall clock, so a consumption another suite left behind expires on the same timeline.
	readonly FakeTimeProvider _clock = new(DateTimeOffset.UtcNow);

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <summary>The current test's cancellation token.</summary>
	protected static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	/// <summary>
	///     Both tables' indexes and columns, read from the provider's catalog, in the provider's own spelling and in
	///     ordinal order.
	/// </summary>
	/// <param name="context">A context on the fixture's database.</param>
	protected abstract Task<List<string>> CatalogAsync(NorseIdentityDbContext context);

	/// <summary>What <see cref="CatalogAsync" /> must read: the physical names written out, never asked of the model.</summary>
	protected abstract IReadOnlyList<string> ExpectedCatalog { get; }

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task The_first_consumption_succeeds()
	{
		fixture.SkipUnlessAvailable();
		var state = NewState();

		(await (await LedgerAsync()).TryConsumeAsync(state, _clock.GetUtcNow().AddMinutes(5), Cancellation)).ShouldBeTrue();

		(await RowsAsync(state)).ShouldBe(1);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_second_consumption_of_the_same_state_fails()
	{
		fixture.SkipUnlessAvailable();
		var state = NewState();
		(await (await LedgerAsync()).TryConsumeAsync(state, _clock.GetUtcNow().AddMinutes(5), Cancellation)).ShouldBeTrue();

		// A later request: its own scope, its own context.
		(await (await LedgerAsync()).TryConsumeAsync(state, _clock.GetUtcNow().AddMinutes(5), Cancellation)).ShouldBeFalse();

		(await RowsAsync(state)).ShouldBe(1);
	}

	// Past its expiry and the skew margin the state itself is refused by its protector, so forgetting its consumption
	// is safe; a consumption still live is kept.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Expired_rows_are_pruned_on_the_next_consumption()
	{
		fixture.SkipUnlessAvailable();
		byte[] expiring = NewState(), live = NewState(), next = NewState();
		(await (await LedgerAsync()).TryConsumeAsync(expiring, _clock.GetUtcNow().AddMinutes(5), Cancellation)).ShouldBeTrue();
		(await (await LedgerAsync()).TryConsumeAsync(live, _clock.GetUtcNow().AddHours(1), Cancellation)).ShouldBeTrue();

		_clock.Advance(TimeSpan.FromMinutes(11));
		(await (await LedgerAsync()).TryConsumeAsync(next, _clock.GetUtcNow().AddMinutes(5), Cancellation)).ShouldBeTrue();

		(await RowsAsync(expiring)).ShouldBe(0);
		(await RowsAsync(live)).ShouldBe(1);
		(await RowsAsync(next)).ShouldBe(1);
	}

	// The protector that judges a state's expiry may run on a replica whose clock trails this one: a consumption just
	// past its expiry is kept for the skew margin, so a lagging replica's still-valid replay is refused, never minted.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_row_inside_the_skew_margin_survives_the_prune()
	{
		fixture.SkipUnlessAvailable();
		byte[] skewed = NewState(), next = NewState();
		(await (await LedgerAsync()).TryConsumeAsync(skewed, _clock.GetUtcNow().AddMinutes(5), Cancellation)).ShouldBeTrue();

		_clock.Advance(TimeSpan.FromMinutes(9));
		(await (await LedgerAsync()).TryConsumeAsync(next, _clock.GetUtcNow().AddMinutes(5), Cancellation)).ShouldBeTrue();

		(await RowsAsync(skewed)).ShouldBe(1);
		(await (await LedgerAsync()).TryConsumeAsync(skewed, _clock.GetUtcNow().AddMinutes(5), Cancellation)).ShouldBeFalse();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Two_concurrent_consumptions_of_one_state_succeed_once()
	{
		fixture.SkipUnlessAvailable();

		// Several rounds, each a fresh state on two fresh contexts, so the race is actually run, not just won.
		for (var round = 0; round < 5; round++)
		{
			var state = NewState();
			var expiresAt = _clock.GetUtcNow().AddMinutes(5);
			var first = await LedgerAsync();
			var second = await LedgerAsync();

			var consumed = await Task.WhenAll(
				first.TryConsumeAsync(state, expiresAt, Cancellation).AsTask(),
				second.TryConsumeAsync(state, expiresAt, Cancellation).AsTask());

			consumed.Count(static c => c).ShouldBe(1);
			(await RowsAsync(state)).ShouldBe(1);
		}
	}

	/// <summary>
	///     The registered ledger shares the request's context with the store: a refused consumption tracks nothing and
	///     classifies nothing, so the store's next write on that same context goes through.
	/// </summary>
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_replay_leaves_the_context_clean()
	{
		fixture.SkipUnlessAvailable();
		using var scope = fixture.CreateOwnedScope();
		var services = scope.ServiceProvider;
		var ledger = services.GetRequiredService<IPasskeyChallengeLedger>();
		var context = services.GetRequiredService<NorseIdentityDbContext>();
		var state = NewState();
		(await ledger.TryConsumeAsync(state, DateTimeOffset.UtcNow.AddMinutes(5), Cancellation)).ShouldBeTrue();

		(await ledger.TryConsumeAsync(state, DateTimeOffset.UtcNow.AddMinutes(5), Cancellation)).ShouldBeFalse();

		context.ChangeTracker.Entries().ShouldBeEmpty();
		var email = $"ledger-{Guid.NewGuid():N}@example.com";
		(await services.GetRequiredService<UserManager<NorseUser>>().CreateAsync(new() { UserName = email, Email = email }))
			.Succeeded.ShouldBeTrue();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task The_tables_exist_with_their_keys()
	{
		fixture.SkipUnlessAvailable();
		var (context, _) = await fixture.CreateScopeAsync();

		(await CatalogAsync(context)).ShouldBe(ExpectedCatalog);
	}

	/// <summary>A ledger on a new scope's context, over the suite's clock.</summary>
	async Task<PasskeyChallengeLedger> LedgerAsync()
	{
		var (context, _) = await fixture.CreateScopeAsync();
		return new(context, _clock);
	}

	/// <summary>How many ledger rows hold <paramref name="state" />'s hash, on a fresh context.</summary>
	async Task<int> RowsAsync(byte[] state)
	{
		var (context, _) = await fixture.CreateScopeAsync();
		var hash = PasskeyChallengeLedger.Hash(state);
		return await context.Set<ConsumedPasskeyChallenge>().CountAsync(c => c.ChallengeHash == hash, Cancellation);
	}

	static byte[] NewState() =>
		RandomNumberGenerator.GetBytes(48);
}
