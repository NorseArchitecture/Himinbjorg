using System.Diagnostics.Metrics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.Metrics.Testing;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Norse.Identity.Web.Server.Verification;

namespace Norse.Identity.Web.Server.Tests.Verification;

/// <summary>
///     The stranded-account verification job (T3-28, Glitnir §2.2) over a scripted query: it runs at startup and on
///     each interval, reports a candidate only when the next run's recheck still finds it stranded, reports the
///     confirmed count on its gauge, and survives a failing query with its pending set intact. Its registration
///     fails fast on a non-positive interval (Glitnir §2.7).
/// </summary>
public sealed class IdentityInvariantVerificationServiceTests : IAsyncDisposable
{
	static readonly TimeSpan _interval = TimeSpan.FromHours(1);

	readonly FakeTimeProvider _clock = new();
	readonly FakeLogger<IdentityInvariantVerificationService> _logger = new();
	readonly FakeStrandedAccountsQuery _query = new();
	readonly ServiceProvider _services;
	IdentityInvariantVerificationService? _service;

	public IdentityInvariantVerificationServiceTests()
	{
		ServiceCollection services = new();
		services.AddMetrics();
		services.AddSingleton<IStrandedAccountsQuery>(_query);
		_services = services.BuildServiceProvider();
	}

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	/// <inheritdoc />
	public async ValueTask DisposeAsync()
	{
		if (_service is not null)
		{
			await _service.StopAsync(CancellationToken.None);
			_service.Dispose();
		}

		await _services.DisposeAsync();
	}

	[Fact]
	async Task A_candidate_is_not_reported_before_its_recheck()
	{
		Guid candidate = new("6a1c1f4e-0000-4000-8000-000000000001");
		_query.Serve(Page(candidate));

		await StartAsync();

		Critical().ShouldBeEmpty();
	}

	[Fact]
	async Task A_candidate_still_stranded_on_the_next_run_logs_critical_with_the_count_and_id()
	{
		Guid candidate = new("6a1c1f4e-0000-4000-8000-000000000002");
		_query.Serve(Page(candidate), Page());
		await StartAsync();

		await NextRunAsync(2);

		var critical = Critical().ShouldHaveSingleItem();
		critical.Message.ShouldBe(
			$"Identity invariant violated: 1 account(s) have no password and no external login: {candidate}");
		_query.Rechecked.Count(ids => ids is [var only] && only == candidate).ShouldBe(1);
	}

	[Fact]
	async Task A_candidate_that_gains_a_login_before_its_recheck_is_never_reported()
	{
		Guid candidate = new("6a1c1f4e-0000-4000-8000-000000000003");
		_query.Serve(Page(candidate), Page());
		_query.Recheck = static _ => ValueTask.FromResult<Guid[]>([]);
		await StartAsync();

		await NextRunAsync(2);
		await NextRunAsync(3);

		Critical().ShouldBeEmpty();
	}

	[Fact]
	async Task A_clean_run_logs_nothing_above_information()
	{
		await StartAsync();

		await NextRunAsync(2);

		_logger.Collector.GetSnapshot().ShouldAllBe(static record => record.Level <= LogLevel.Information);
	}

	[Fact]
	async Task A_query_failure_logs_an_error_keeps_the_pending_set_and_keeps_running()
	{
		Guid candidate = new("6a1c1f4e-0000-4000-8000-000000000004");
		_query.Serve(Page(candidate), Page());
		var rechecks = 0;
		_query.Recheck = ids => ++rechecks is 2 ?
			ValueTask.FromException<Guid[]>(new InvalidOperationException("The database is down.")) :
			ValueTask.FromResult(ids.ToArray());
		await StartAsync();

		await NextRunAsync(2);

		var error = _logger.Collector.GetSnapshot().Single(static record => record.Level is LogLevel.Error);
		error.Exception.ShouldBeOfType<InvalidOperationException>();
		Critical().ShouldBeEmpty();
		// The failed run never reached the page, so the cursor was not advanced.
		_query.PageSizes.Count.ShouldBe(1);

		await NextRunAsync(3);

		_service.ShouldNotBeNull().ExecuteTask.ShouldNotBeNull().IsCompleted.ShouldBeFalse();
		Critical().ShouldHaveSingleItem().Message.ShouldContain(candidate.ToString());
	}

	[Fact]
	async Task It_runs_at_startup_and_on_each_interval()
	{
		await StartAsync();
		_query.PageSizes.ShouldBe([100]);

		_clock.Advance(_interval / 2);
		await Task.Delay(TimeSpan.FromMilliseconds(100), Cancellation);
		_query.PageSizes.Count.ShouldBe(1);

		_clock.Advance(_interval / 2);
		await WaitForRunsAsync(_logger.Collector, 2);
		await NextRunAsync(3);

		_query.PageSizes.ShouldBe([100, 100, 100]);
	}

	[Fact]
	async Task The_gauge_reports_the_confirmed_count()
	{
		Guid first = new("6a1c1f4e-0000-4000-8000-000000000005"), second = new("6a1c1f4e-0000-4000-8000-000000000006");
		_query.Serve(Page(first, second), Page());
		using MetricCollector<int> gauge = new(_services.GetRequiredService<IMeterFactory>(), "Norse.Identity",
			"norse.identity.stranded_accounts");
		await StartAsync();
		gauge.LastMeasurement.ShouldNotBeNull().Value.ShouldBe(0);

		await NextRunAsync(2);

		gauge.LastMeasurement.ShouldNotBeNull().Value.ShouldBe(2);
	}

	[Fact]
	async Task A_disabled_service_queries_nothing()
	{
		_service = Create(new() { Enabled = false });

		await _service.StartAsync(Cancellation);
		await _service.ExecuteTask.ShouldNotBeNull().WaitAsync(TimeSpan.FromSeconds(10), Cancellation);

		_query.Calls.ShouldBe(0);
		_logger.Collector.GetSnapshot().ShouldHaveSingleItem().Level.ShouldBe(LogLevel.Information);
	}

	[Theory]
	[InlineData("00:00:00")]
	[InlineData("-00:01:00")]
	async Task A_non_positive_interval_fails_at_startup(string interval)
	{
		var builder = Host.CreateApplicationBuilder();
		builder.Configuration[$"{IdentityVerificationOptions.Section}:{nameof(IdentityVerificationOptions.Interval)}"] = interval;
		builder.Services.AddNorseIdentityInvariantVerification(builder.Configuration);
		using var host = builder.Build();

		var failure = await Should.ThrowAsync<OptionsValidationException>(() => host.StartAsync(Cancellation));

		failure.OptionsType.ShouldBe(typeof(IdentityVerificationOptions));
	}

	// Bounded at one day: PeriodicTimer refuses more than about 49.7 days with a framework exception that names no
	// setting, and a verification that rarely runs is no verification.
	[Theory]
	[InlineData("1.00:00:01")]
	[InlineData("60.00:00:00")]
	async Task An_interval_over_a_day_fails_at_startup_naming_the_setting(string interval)
	{
		var builder = Host.CreateApplicationBuilder();
		builder.Configuration[$"{IdentityVerificationOptions.Section}:{nameof(IdentityVerificationOptions.Interval)}"] = interval;
		builder.Services.AddNorseIdentityInvariantVerification(builder.Configuration);
		using var host = builder.Build();

		var failure = await Should.ThrowAsync<OptionsValidationException>(() => host.StartAsync(Cancellation));

		failure.OptionsType.ShouldBe(typeof(IdentityVerificationOptions));
		failure.Message.ShouldContain("Identity:Verification:Interval must be at most 1.00:00:00.");
	}

	[Fact]
	async Task An_interval_of_exactly_a_day_starts()
	{
		var builder = Host.CreateApplicationBuilder();
		builder.Configuration[$"{IdentityVerificationOptions.Section}:{nameof(IdentityVerificationOptions.Interval)}"] = "1.00:00:00";
		builder.Configuration[$"{IdentityVerificationOptions.Section}:{nameof(IdentityVerificationOptions.Enabled)}"] = "false";
		builder.Services.AddNorseIdentityInvariantVerification(builder.Configuration);
		using var host = builder.Build();

		await host.StartAsync(Cancellation);
		await host.StopAsync(Cancellation);
	}

	[Fact]
	void Registration_adds_the_options_the_scoped_query_the_hosted_service_and_a_default_clock()
	{
		ServiceCollection services = new();
		TimeProvider hostClock = new FakeTimeProvider();
		services.AddSingleton(hostClock);

		services.AddNorseIdentityInvariantVerification(new ConfigurationBuilder().Build());

		var query = services.Where(static d => d.ServiceType == typeof(IStrandedAccountsQuery)).ShouldHaveSingleItem();
		query.ImplementationType.ShouldBe(typeof(StrandedAccountsQuery));
		query.Lifetime.ShouldBe(ServiceLifetime.Scoped);
		services.ShouldContain(static d => d.ServiceType == typeof(IHostedService) &&
			d.ImplementationType == typeof(IdentityInvariantVerificationService));
		services.ShouldContain(static d => d.ServiceType == typeof(IValidateOptions<IdentityVerificationOptions>));
		// TryAdd: a host's own clock wins.
		services.Where(static d => d.ServiceType == typeof(TimeProvider)).ShouldHaveSingleItem().ImplementationInstance
			.ShouldBeSameAs(hostClock);
		ServiceCollection bare = new();
		bare.AddNorseIdentityInvariantVerification(new ConfigurationBuilder().Build());
		bare.Where(static d => d.ServiceType == typeof(TimeProvider)).ShouldHaveSingleItem().ImplementationInstance
			.ShouldBeSameAs(TimeProvider.System);
		using var provider = services.BuildServiceProvider();
		provider.GetRequiredService<IOptions<IdentityVerificationOptions>>().Value.ShouldSatisfyAllConditions(
			static options => options.Enabled.ShouldBeTrue(),
			static options => options.Interval.ShouldBe(TimeSpan.FromHours(1)),
			static options => options.SampleSize.ShouldBe(100));
	}

	/// <summary>
	///     Waits until <paramref name="runs" /> runs have finished, successfully or not: each run ends with exactly one
	///     page line or one failure line.
	/// </summary>
	/// <param name="collector">The service's log collector.</param>
	/// <param name="runs">The number of finished runs to wait for.</param>
	internal static async Task WaitForRunsAsync(FakeLogCollector collector, int runs)
	{
		using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Cancellation);
		timeout.CancelAfter(TimeSpan.FromSeconds(60));
		while (collector.GetSnapshot().Count(IsRunEnd) < runs)
			await Task.Delay(TimeSpan.FromMilliseconds(5), timeout.Token);

		static bool IsRunEnd(FakeLogRecord record) =>
			record.Id.Id is IdentityInvariantVerificationService.PageEventId or IdentityInvariantVerificationService.FailureEventId;
	}

	static StrandedPage Page(params Guid[] candidates) =>
		new(candidates, null, true, true);

	IdentityInvariantVerificationService Create(IdentityVerificationOptions options) =>
		new(_services.GetRequiredService<IServiceScopeFactory>(), Options.Create(options), _logger,
			_services.GetRequiredService<IMeterFactory>(), _clock);

	async Task StartAsync()
	{
		_service = Create(new() { Interval = _interval });
		await _service.StartAsync(Cancellation);
		await WaitForRunsAsync(_logger.Collector, 1);
	}

	async Task NextRunAsync(int run)
	{
		_clock.Advance(_interval);
		await WaitForRunsAsync(_logger.Collector, run);
	}

	IReadOnlyList<FakeLogRecord> Critical() =>
		[.. _logger.Collector.GetSnapshot().Where(static record => record.Level is LogLevel.Critical)];
}
