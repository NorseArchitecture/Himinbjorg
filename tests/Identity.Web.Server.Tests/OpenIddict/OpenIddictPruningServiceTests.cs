using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Norse.Identity.Web.Server.OpenIddict;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     The OpenIddict pruner's loop (2026-10-29 OpenIddict spec §5.6, plan Task 4.8) over substituted managers: it runs at
///     startup and on each interval, prunes tokens, then sessions, then authorizations at one threshold through the
///     <c>.Outcome</c> views, and a failed run logs an Error and never stops the host. Its options are validated on start,
///     the minimum age against the OpenIddict server's own refresh token lifetime. <see cref="PruningSuite" /> proves what
///     a run removes from a real database.
/// </summary>
public sealed class OpenIddictPruningServiceTests : IAsyncDisposable
{
	static readonly TimeSpan _interval = TimeSpan.FromHours(1);
	static readonly TimeSpan _minimumAge = TimeSpan.FromDays(14);

	readonly IOpenIddictAuthorizationManager _authorizations = Substitute.For<IOpenIddictAuthorizationManager>();
	readonly X509Certificate2 _certificate = IdentityTestCertificate.CreateFresh();
	readonly FakeTimeProvider _clock = new(new(2026, 10, 30, 12, 0, 0, TimeSpan.Zero));
	readonly FakeLogger<OpenIddictPruningService> _logger = new();
	readonly ServiceProvider _services;
	readonly IOpenIddictSessionManager _sessions = Substitute.For<IOpenIddictSessionManager>();
	readonly IOpenIddictTokenManager _tokens = Substitute.For<IOpenIddictTokenManager>();
	OpenIddictPruningService? _service;

	public OpenIddictPruningServiceTests()
	{
		ServiceCollection services = new();
		services.AddSingleton(_tokens).AddSingleton(_sessions).AddSingleton(_authorizations);
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
		_certificate.Dispose();
	}

	[Fact]
	async Task A_run_prunes_tokens_then_sessions_then_authorizations_at_one_threshold()
	{
		await StartAsync();

		var threshold = _clock.GetUtcNow() - _minimumAge;
		Received.InOrder(() =>
		{
			_tokens.PruneAsync(threshold, Arg.Any<CancellationToken>());
			_sessions.PruneAsync(threshold, Arg.Any<CancellationToken>());
			_authorizations.PruneAsync(threshold, Arg.Any<CancellationToken>());
		});
	}

	[Fact]
	async Task It_runs_at_startup_and_on_each_interval()
	{
		await StartAsync();
		await _tokens.Received(1).PruneAsync(Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());

		_clock.Advance(_interval / 2);
		await Task.Delay(TimeSpan.FromMilliseconds(100), Cancellation);
		await _tokens.Received(1).PruneAsync(Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());

		_clock.Advance(_interval / 2);
		await WaitForRunsAsync(2);

		await _authorizations.Received(2).PruneAsync(Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());
		var thresholds = _tokens.ReceivedCalls().Select(static call => (DateTimeOffset)call.GetArguments()[0]!).ToArray();
		thresholds[1].ShouldBe(thresholds[0] + _interval, "each run's threshold follows the clock");
	}

	[Fact]
	async Task A_successful_run_logs_its_counts_at_information()
	{
		_tokens.PruneAsync(Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>()).Returns(3L);
		_sessions.PruneAsync(Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>()).Returns(2L);
		_authorizations.PruneAsync(Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>()).Returns(1L);

		await StartAsync();

		var run = _logger.Collector.GetSnapshot().Single(static record => record.Id.Id is OpenIddictPruningService.RunEventId);
		run.Level.ShouldBe(LogLevel.Information);
		run.Message.ShouldBe("Pruned 3 token(s), 2 session(s) and 1 authorization(s) created before 10/16/2026 12:00:00 +00:00.");
	}

	[Fact]
	async Task A_failed_run_logs_an_error_and_the_next_run_proceeds()
	{
		var calls = 0;
		_tokens.PruneAsync(Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>())
			.Returns(_ => ++calls is 1 ?
				ValueTask.FromException<long>(new InvalidOperationException("The database is down.")) :
				ValueTask.FromResult(4L));
		await StartAsync();

		var error = _logger.Collector.GetSnapshot().Single(static record => record.Level is LogLevel.Error);
		error.Id.Id.ShouldBe(OpenIddictPruningService.FailureEventId);
		error.Exception.ShouldBeOfType<InvalidOperationException>();
		// The run ended at its failed step: nothing past the tokens was pruned on a run that could not prune them.
		await _sessions.DidNotReceive().PruneAsync(Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());
		await _authorizations.DidNotReceive().PruneAsync(Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());

		await NextRunAsync(2);

		_service.ShouldNotBeNull().ExecuteTask.ShouldNotBeNull().IsCompleted.ShouldBeFalse();
		await _sessions.Received(1).PruneAsync(Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());
		await _authorizations.Received(1).PruneAsync(Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());
		_logger.Collector.GetSnapshot().Count(static record => record.Id.Id is OpenIddictPruningService.RunEventId).ShouldBe(1);
	}

	[Fact]
	async Task A_failed_step_outcome_logs_an_error_naming_the_step_and_ends_the_run()
	{
		_sessions.PruneAsync(Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>())
			.ThrowsAsync(new OpenIddictExceptions.ValidationException("ID2000"));

		await StartAsync();

		var error = _logger.Collector.GetSnapshot().Single(static record => record.Level is LogLevel.Error);
		error.Id.Id.ShouldBe(OpenIddictPruningService.StepFailedEventId);
		error.Message.ShouldBe("Pruning OpenIddict sessions failed (Fault); the run ended there and the next run retries.");
		await _authorizations.DidNotReceive().PruneAsync(Arg.Any<DateTimeOffset>(), Arg.Any<CancellationToken>());
	}

	[Fact]
	async Task A_disabled_service_prunes_nothing_and_logs_once()
	{
		_service = Create(new() { Enabled = false });

		await _service.StartAsync(Cancellation);
		await _service.ExecuteTask.ShouldNotBeNull().WaitAsync(TimeSpan.FromSeconds(10), Cancellation);

		_tokens.ReceivedCalls().ShouldBeEmpty();
		_sessions.ReceivedCalls().ShouldBeEmpty();
		_authorizations.ReceivedCalls().ShouldBeEmpty();
		var record = _logger.Collector.GetSnapshot().ShouldHaveSingleItem();
		record.Level.ShouldBe(LogLevel.Information);
		record.Id.Id.ShouldBe(OpenIddictPruningService.DisabledEventId, "named like its siblings (M5)");
	}

	[Fact]
	void The_defaults_are_enabled_hourly_and_fourteen_days()
	{
		using var provider = Compose([]).BuildServiceProvider();

		provider.GetRequiredService<IOptions<OpenIddictPruningOptions>>().Value.ShouldSatisfyAllConditions(
			static options => options.Enabled.ShouldBeTrue(),
			static options => options.Interval.ShouldBe(TimeSpan.FromHours(1)),
			static options => options.MinimumAge.ShouldBe(TimeSpan.FromDays(14)));
	}

	[Theory]
	[InlineData("00:00:00", "Identity:OpenIddict:Pruning:Interval must be positive.")]
	[InlineData("-00:01:00", "Identity:OpenIddict:Pruning:Interval must be positive.")]
	[InlineData("1.00:00:01", "Identity:OpenIddict:Pruning:Interval must be at most 1.00:00:00.")]
	void An_interval_outside_zero_to_a_day_is_refused_naming_the_setting(string interval, string message)
	{
		using var provider = Compose([new("Identity:OpenIddict:Pruning:Interval", interval)]).BuildServiceProvider();

		var failure = Should.Throw<OptionsValidationException>(() =>
			provider.GetRequiredService<IOptions<OpenIddictPruningOptions>>().Value);

		failure.Message.ShouldContain(message);
	}

	[Fact]
	void An_interval_of_exactly_a_day_is_accepted()
	{
		using var provider = Compose([new("Identity:OpenIddict:Pruning:Interval", "1.00:00:00")]).BuildServiceProvider();

		provider.GetRequiredService<IOptions<OpenIddictPruningOptions>>().Value.Interval.ShouldBe(TimeSpan.FromDays(1));
	}

	// The floor is the server's configured refresh token lifetime, read from OpenIddict's own options: a redeemed refresh
	// token pruned while it could still be replayed would turn a reuse (which ends the grant) into an unknown token.
	[Fact]
	void A_minimum_age_below_the_refresh_lifetime_is_refused()
	{
		using var provider = Compose([new("Identity:OpenIddict:Pruning:MinimumAge", "13.23:59:59")]).BuildServiceProvider();

		var failure = Should.Throw<OptionsValidationException>(() =>
			provider.GetRequiredService<IOptions<OpenIddictPruningOptions>>().Value);

		failure.Message.ShouldContain(
			"Identity:OpenIddict:Pruning:MinimumAge must be at least the OpenIddict server's refresh token lifetime, which must be finite.");
	}

	[Fact]
	void The_minimum_age_floor_follows_the_servers_refresh_lifetime()
	{
		var lengthened = Compose([]);
		lengthened.Configure<OpenIddictServerOptions>(static server => server.RefreshTokenLifetime = TimeSpan.FromDays(15));
		using (var provider = lengthened.BuildServiceProvider())
			Should.Throw<OptionsValidationException>(() => provider.GetRequiredService<IOptions<OpenIddictPruningOptions>>().Value);

		var unbounded = Compose([]);
		unbounded.Configure<OpenIddictServerOptions>(static server => server.RefreshTokenLifetime = null);
		using (var provider = unbounded.BuildServiceProvider())
			Should.Throw<OptionsValidationException>(() => provider.GetRequiredService<IOptions<OpenIddictPruningOptions>>().Value);

		var shortened = Compose([new("Identity:OpenIddict:Pruning:MinimumAge", "7.00:00:00")]);
		shortened.Configure<OpenIddictServerOptions>(static server => server.RefreshTokenLifetime = TimeSpan.FromDays(7));
		using (var provider = shortened.BuildServiceProvider())
			provider.GetRequiredService<IOptions<OpenIddictPruningOptions>>().Value.MinimumAge.ShouldBe(TimeSpan.FromDays(7));
	}

	[Fact]
	async Task An_invalid_option_fails_the_host_at_startup()
	{
		var builder = Host.CreateApplicationBuilder();
		builder.Configuration["Identity:OpenIddict:Pruning:Interval"] = "00:00:00";
		builder.Services.AddNorseIdentity(_certificate);
		using var host = builder.Build();

		var failure = await Should.ThrowAsync<OptionsValidationException>(() => host.StartAsync(Cancellation));

		failure.OptionsType.ShouldBe(typeof(OpenIddictPruningOptions));
	}

	[Fact]
	void AddNorseIdentity_registers_the_hosted_pruner()
	{
		ServiceCollection services = new();

		services.AddNorseIdentity(_certificate);

		services.ShouldContain(static d => d.ServiceType == typeof(IHostedService) &&
			d.ImplementationType == typeof(OpenIddictPruningService));
		services.ShouldContain(static d => d.ServiceType == typeof(IValidateOptions<OpenIddictPruningOptions>));
	}

	/// <summary><c>AddNorseIdentity</c> over a configuration holding <paramref name="settings" />.</summary>
	ServiceCollection Compose(KeyValuePair<string, string?>[] settings)
	{
		ServiceCollection services = new();
		services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(settings).Build());
		services.AddNorseIdentity(_certificate);
		return services;
	}

	/// <summary>Waits until <paramref name="runs" /> runs have ended, each with exactly one run or failure line.</summary>
	async Task WaitForRunsAsync(int runs)
	{
		using var timeout = CancellationTokenSource.CreateLinkedTokenSource(Cancellation);
		timeout.CancelAfter(TimeSpan.FromSeconds(60));
		while (_logger.Collector.GetSnapshot().Count(IsRunEnd) < runs)
			await Task.Delay(TimeSpan.FromMilliseconds(5), timeout.Token);

		static bool IsRunEnd(FakeLogRecord record) =>
			record.Id.Id is OpenIddictPruningService.RunEventId or OpenIddictPruningService.FailureEventId
				or OpenIddictPruningService.StepFailedEventId;
	}

	OpenIddictPruningService Create(OpenIddictPruningOptions options) =>
		new(_services.GetRequiredService<IServiceScopeFactory>(), Options.Create(options), _logger, _clock);

	async Task StartAsync()
	{
		_service = Create(new() { Interval = _interval, MinimumAge = _minimumAge });
		await _service.StartAsync(Cancellation);
		await WaitForRunsAsync(1);
	}

	async Task NextRunAsync(int run)
	{
		_clock.Advance(_interval);
		await WaitForRunsAsync(run);
	}
}
