using System.Diagnostics.Metrics;
using Microsoft.Extensions.Options;

namespace Norse.Identity.Web.Server.Verification;

/// <summary>
///     The stranded-account verification (T3-28; Glitnir §2.2: an invariant the database can't hold gets a periodic
///     job that fails loudly). No account may be left with neither a password nor an external login. The
///     last-sign-in-method guard keeps every removal from doing that, but no constraint can, so this job walks every
///     account, never a sample, and logs Critical for each one it finds stranded twice.
/// </summary>
/// <remarks>
///     <para>
///         It runs at startup, then every <see cref="IdentityVerificationOptions.Interval" />, one scope per run. A
///         run first rechecks the previous run's candidates (the second sighting) and reports those still stranded,
///         then reads the next page and keeps its candidates, less those just reported, for the next run. Two
///         sightings absorb the window between <c>CreateAsync</c> and <c>AddLoginAsync</c>: an account that gains a
///         login before its recheck is never reported.
///     </para>
///     <para>
///         The bound: the cursor advances monotonically within a traversal (compare-and-set), so for a stable account
///         population every account is visited within ceil(N / <see cref="IdentityVerificationOptions.SampleSize" />)
///         successful advances counted from a traversal start, or ceil(N / SampleSize) + 1 from a cursor in the middle
///         of a page, across however many replicas run, and a stranded account is reported on the observing replica's
///         next successful run. Concurrent inserts, deletions, failures and restarts rule out an unconditional
///         fixed-run guarantee, and none is claimed. A restart forgets the pending candidates and delays their report
///         until the next traversal.
///     </para>
///     <para>
///         A failing run logs an Error, keeps its pending set, leaves the cursor where it was, and never stops the
///         host. A lost compare-and-set is another replica's progress, logged at Debug only.
///     </para>
/// </remarks>
/// <param name="scopeFactory">Creates each run's scope.</param>
/// <param name="options">The verification options.</param>
/// <param name="logger">The logger.</param>
/// <param name="meterFactory">Creates the <c>Norse.Identity</c> meter.</param>
/// <param name="timeProvider">The clock the interval runs on.</param>
sealed partial class IdentityInvariantVerificationService(IServiceScopeFactory scopeFactory,
	IOptions<IdentityVerificationOptions> options, ILogger<IdentityInvariantVerificationService> logger,
	IMeterFactory meterFactory, TimeProvider timeProvider) : BackgroundService
{
	/// <summary>The event id of the Debug line every successful run ends with.</summary>
	internal const int PageEventId = 1;

	/// <summary>The event id of the Error line a failed run ends with.</summary>
	internal const int FailureEventId = 2;

	readonly Gauge<int> _stranded = meterFactory.Create("Norse.Identity").CreateGauge<int>("norse.identity.stranded_accounts",
		"{account}", "Accounts confirmed to have no password and no external login on the latest run.");

	/// <inheritdoc />
	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		var settings = options.Value;
		if (!settings.Enabled)
		{
			LogDisabled(logger);
			return;
		}

		// Created before the first run, so the first interval counts from startup.
		using PeriodicTimer timer = new(settings.Interval, timeProvider);
		Guid[] pending = [];
		do
			pending = await RunAsync(pending, settings.SampleSize, stoppingToken).ConfigureAwait(false);
		while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
	}

	/// <summary>One run: the recheck, the report, then the next page.</summary>
	/// <returns>The candidates the next run rechecks.</returns>
	async Task<Guid[]> RunAsync(Guid[] pending, int sampleSize, CancellationToken stoppingToken)
	{
		try
		{
			var scope = scopeFactory.CreateAsyncScope();
			await using (scope.ConfigureAwait(false))
			{
				var query = scope.ServiceProvider.GetRequiredService<IStrandedAccountsQuery>();
				var confirmed = await query.StillStrandedAsync(pending, stoppingToken).ConfigureAwait(false);
				if (confirmed.Length is not 0)
					LogStranded(logger, confirmed.Length, confirmed);
				_stranded.Record(confirmed.Length);

				var page = await query.NextPageAsync(sampleSize, stoppingToken).ConfigureAwait(false);
				if (!page.Advanced)
					LogLostAdvance(logger);
				LogPage(logger, page.Candidates.Length, page.NextCursor, page.Wrapped);
				return [.. page.Candidates.Except(confirmed)];
			}
		}
		catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
		{
			LogFailed(logger, exception);
			return pending;
		}
	}

	[LoggerMessage(Level = LogLevel.Information,
		Message = "The stranded-account verification is disabled (Identity:Verification:Enabled is false).")]
	static partial void LogDisabled(ILogger logger);

	[LoggerMessage(Level = LogLevel.Critical,
		Message = "Identity invariant violated: {Count} account(s) have no password and no external login: {UserIds}")]
	static partial void LogStranded(ILogger logger, int count, Guid[] userIds);

	[LoggerMessage(Level = LogLevel.Debug,
		Message = "Another replica advanced the stranded-account cursor first; this run's advance was discarded.")]
	static partial void LogLostAdvance(ILogger logger);

	[LoggerMessage(EventId = PageEventId, Level = LogLevel.Debug,
		Message = "Stranded-account verification page: {Candidates} candidate(s); the cursor is at {NextCursor} (wrapped: {Wrapped}).")]
	static partial void LogPage(ILogger logger, int candidates, Guid? nextCursor, bool wrapped);

	[LoggerMessage(EventId = FailureEventId, Level = LogLevel.Error,
		Message = "The stranded-account verification run failed; its candidates are kept for the next run.")]
	static partial void LogFailed(ILogger logger, Exception exception);
}
