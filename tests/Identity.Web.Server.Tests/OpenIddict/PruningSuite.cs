using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using Microsoft.Extensions.Options;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.OpenIddict;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     The OpenIddict pruner against a real database (2026-10-29 OpenIddict spec §5.6, §10 item 14; plan Task 4.8), once
///     per provider: one run of the production <see cref="OpenIddictPruningService" />, over the production composition's
///     managers and Norse stores, removes what OpenIddict's own <c>PruneAsync</c> semantics name past
///     <see cref="OpenIddictPruningOptions.MinimumAge" /> and keeps everything else.
/// </summary>
/// <remarks>
///     <para>
///         The order is the foreign keys': <c>tokens</c> reference <c>sessions</c> and <c>authorizations</c>, and
///         <c>sessions</c> reference <c>authorizations</c>, every one without a cascade. A session's prune skips any
///         session a token still references, and an authorization's skips any a token references but not one a session
///         references, so pruning authorizations before sessions would fail on the session's key. One run removing a whole
///         chain proves the order.
///     </para>
///     <para>
///         Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///         records: xUnit discovers them on each <see langword="sealed" /> provider class. Every assertion reads only the
///         rows its fact seeded, since the database is the collection's.
///     </para>
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class PruningSuite(IdentityFixture fixture)
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	static readonly TimeSpan _minimumAge = TimeSpan.FromDays(14);

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	/// <summary>Past the minimum age.</summary>
	static DateTime Old => DateTime.UtcNow.AddDays(-30);

	/// <summary>Inside the minimum age.</summary>
	static DateTime Recent => DateTime.UtcNow.AddDays(-1);

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Prunes_tokens_then_sessions_then_authorizations_past_minimum_age()
	{
		fixture.SkipUnlessAvailable();
		NorseOpenIddictAuthorization revoked = Authorization(Old, Statuses.Revoked, AuthorizationTypes.Permanent),
			adHoc = Authorization(Old, Statuses.Valid, AuthorizationTypes.AdHoc);
		var session = Session(Old, Statuses.Revoked, revoked.Id);
		NorseOpenIddictToken redeemed = Token(Old, Statuses.Redeemed, DateTime.UtcNow.AddDays(1), revoked.Id, session.Id),
			expired = Token(Old, Statuses.Valid, DateTime.UtcNow.AddDays(-1));
		await SeedAsync(revoked, adHoc, session, redeemed, expired);

		var log = await RunOnceAsync(new() { MinimumAge = _minimumAge });

		log.ShouldNotContain(static record => record.Level >= LogLevel.Error);
		(await RemainingAsync(revoked.Id, adHoc.Id, session.Id, redeemed.Id, expired.Id)).ShouldBeEmpty();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Live_rows_are_kept()
	{
		fixture.SkipUnlessAvailable();
		NorseOpenIddictAuthorization permanent = Authorization(Old, Statuses.Valid, AuthorizationTypes.Permanent),
			recentAuthorization = Authorization(Recent, Statuses.Revoked, AuthorizationTypes.Permanent);
		NorseOpenIddictSession live = Session(Old, Statuses.Valid),
			recentSession = Session(Recent, Statuses.Revoked);
		NorseOpenIddictToken unexpired = Token(Old, Statuses.Valid, DateTime.UtcNow.AddDays(1), permanent.Id),
			recentToken = Token(Recent, Statuses.Revoked, DateTime.UtcNow.AddDays(-1));
		await SeedAsync(permanent, recentAuthorization, live, recentSession, unexpired, recentToken);
		Guid[] seeded = [permanent.Id, recentAuthorization.Id, live.Id, recentSession.Id, unexpired.Id, recentToken.Id];

		var log = await RunOnceAsync(new() { MinimumAge = _minimumAge });

		log.ShouldNotContain(static record => record.Level >= LogLevel.Error);
		(await RemainingAsync(seeded)).ShouldBe(seeded, ignoreOrder: true);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_session_with_an_attached_token_survives_until_its_token_is_pruned()
	{
		fixture.SkipUnlessAvailable();
		var session = Session(Old, Statuses.Revoked);
		var token = Token(Old, Statuses.Valid, DateTime.UtcNow.AddDays(1), session: session.Id);
		await SeedAsync(session, token);

		await RunOnceAsync(new() { MinimumAge = _minimumAge });

		(await RemainingAsync(session.Id, token.Id)).ShouldBe([session.Id, token.Id], ignoreOrder: true);

		var (context, _) = await fixture.CreateScopeAsync();
		(await context.Set<NorseOpenIddictToken>()
			.Where(t => t.Id == token.Id)
			.ExecuteUpdateAsync(static setters => setters.SetProperty(static t => t.Status, Statuses.Revoked), Cancellation)).ShouldBe(1);

		await RunOnceAsync(new() { MinimumAge = _minimumAge });

		(await RemainingAsync(session.Id, token.Id)).ShouldBeEmpty();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Disabled_prunes_nothing()
	{
		fixture.SkipUnlessAvailable();
		var authorization = Authorization(Old, Statuses.Revoked, AuthorizationTypes.Permanent);
		var session = Session(Old, Statuses.Revoked, authorization.Id);
		var token = Token(Old, Statuses.Redeemed, DateTime.UtcNow.AddDays(-1), authorization.Id, session.Id);
		await SeedAsync(authorization, session, token);
		Guid[] seeded = [authorization.Id, session.Id, token.Id];

		var log = await RunOnceAsync(new() { Enabled = false, MinimumAge = _minimumAge });

		log.ShouldHaveSingleItem().Level.ShouldBe(LogLevel.Information);
		(await RemainingAsync(seeded)).ShouldBe(seeded, ignoreOrder: true);
	}

	/// <summary>
	///     Starts a pruner over the fixture's production services, waits for its first run (or, disabled, its exit) and
	///     stops it.
	/// </summary>
	/// <returns>Everything the run logged.</returns>
	async Task<IReadOnlyList<FakeLogRecord>> RunOnceAsync(OpenIddictPruningOptions options)
	{
		using var scope = fixture.CreateOwnedScope();
		FakeLogger<OpenIddictPruningService> logger = new();
		using OpenIddictPruningService service = new(scope.ServiceProvider.GetRequiredService<IServiceScopeFactory>(),
			Options.Create(options), logger, TimeProvider.System);
		await service.StartAsync(Cancellation);
		using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(Cancellation))
		{
			timeout.CancelAfter(TimeSpan.FromSeconds(60));
			while (!service.ExecuteTask.ShouldNotBeNull().IsCompleted && !logger.Collector.GetSnapshot().Any(IsRunEnd))
				await Task.Delay(TimeSpan.FromMilliseconds(5), timeout.Token);
		}

		await service.StopAsync(CancellationToken.None);
		return logger.Collector.GetSnapshot();

		static bool IsRunEnd(FakeLogRecord record) =>
			record.Id.Id is OpenIddictPruningService.RunEventId or OpenIddictPruningService.FailureEventId
				or OpenIddictPruningService.StepFailedEventId;
	}

	async Task SeedAsync(params object[] entities)
	{
		var (context, _) = await fixture.CreateScopeAsync();
		context.AddRange(entities);
		await context.SaveChangesAsync(Cancellation);
	}

	/// <summary>Which of <paramref name="ids" /> are still a token, a session or an authorization.</summary>
	async Task<List<Guid>> RemainingAsync(params Guid[] ids)
	{
		var (context, _) = await fixture.CreateScopeAsync();
		return await context.Set<NorseOpenIddictToken>().Where(t => ids.Contains(t.Id)).Select(static t => t.Id)
			.Concat(context.Set<NorseOpenIddictSession>().Where(s => ids.Contains(s.Id)).Select(static s => s.Id))
			.Concat(context.Set<NorseOpenIddictAuthorization>().Where(a => ids.Contains(a.Id)).Select(static a => a.Id))
			.ToListAsync(Cancellation);
	}

	static NorseOpenIddictAuthorization Authorization(DateTime created, string status, string type) =>
		new()
		{
			Id = Guid.CreateVersion7(),
			CreationDate = created,
			Status = status,
			Subject = $"pruning-{Guid.NewGuid():N}",
			Type = type
		};

	static NorseOpenIddictSession Session(DateTime created, string status, Guid? authorization = null) =>
		new()
		{
			Id = Guid.CreateVersion7(),
			AuthorizationId = authorization,
			CreationDate = created,
			Status = status,
			Subject = $"pruning-{Guid.NewGuid():N}"
		};

	static NorseOpenIddictToken Token(DateTime created, string status, DateTime expires, Guid? authorization = null,
		Guid? session = null) =>
		new()
		{
			Id = Guid.CreateVersion7(),
			AuthorizationId = authorization,
			SessionId = session,
			CreationDate = created,
			ExpirationDate = expires,
			Status = status,
			Subject = $"pruning-{Guid.NewGuid():N}",
			Type = TokenTypeIdentifiers.RefreshToken
		};
}
