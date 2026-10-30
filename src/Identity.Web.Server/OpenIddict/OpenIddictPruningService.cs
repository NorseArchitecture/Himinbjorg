using Microsoft.Extensions.Options;
using Norse.Abstractions.Contracts;
using Norse.Identity.Outcomes;
using OpenIddict.Abstractions;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     The OpenIddict pruner (2026-10-29 OpenIddict spec §5.6): nothing else removes OpenIddict's runtime rows, so this job
///     does, through the <c>.Outcome</c> views over the three managers (§5.8), at one threshold per run,
///     <see cref="OpenIddictPruningOptions.MinimumAge" /> before the run's clock.
/// </summary>
/// <remarks>
///     <para>
///         What each step removes is OpenIddict's own <c>PruneAsync</c> (decompiled 8.0.0-preview.4 EF Core stores), every
///         one limited to rows created before the threshold: tokens that are expired, are neither <c>valid</c> nor
///         <c>inactive</c>, or sit under an authorization that is no longer <c>valid</c>; sessions that are no longer
///         <c>valid</c> and that no token references; authorizations that are ad-hoc or no longer <c>valid</c> and that no
///         token references.
///     </para>
///     <para>
///         The order is the schema's foreign keys, none of which cascades: <c>tokens</c> reference <c>sessions</c> and
///         <c>authorizations</c>, and <c>sessions</c> reference <c>authorizations</c>. So tokens go first, then sessions,
///         then authorizations, as erasure deletes them. The authorization step checks for tokens but not for sessions, so
///         run before the sessions it would fail on a session's key.
///     </para>
///     <para>
///         It runs at startup, then every <see cref="OpenIddictPruningOptions.Interval" />, one scope per run. A step that
///         fails ends its run, since a later step only removes what an earlier one freed; the run logs an Error and the next
///         one starts over. A failed run never stops the host. Every replica prunes; the deletes are idempotent, so
///         concurrent runs only race to remove the same rows.
///     </para>
/// </remarks>
/// <param name="scopeFactory">Creates each run's scope.</param>
/// <param name="options">The pruning options.</param>
/// <param name="logger">The logger.</param>
/// <param name="timeProvider">The clock the interval runs on and the threshold is read from.</param>
sealed partial class OpenIddictPruningService(IServiceScopeFactory scopeFactory, IOptions<OpenIddictPruningOptions> options,
	ILogger<OpenIddictPruningService> logger, TimeProvider timeProvider) : BackgroundService
{
	/// <summary>The event id of the Information line every successful run ends with.</summary>
	internal const int RunEventId = 1;

	/// <summary>The event id of the Error line a run that threw ends with.</summary>
	internal const int FailureEventId = 2;

	/// <summary>The event id of the Error line a run ends with when a step answers a failed outcome.</summary>
	internal const int StepFailedEventId = 3;

	/// <summary>The event id of the Information line a disabled pruner logs once, at start.</summary>
	internal const int DisabledEventId = 4;

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
		do
			await RunAsync(settings.MinimumAge, stoppingToken).ConfigureAwait(false);
		while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
	}

	/// <summary>One run: tokens, then sessions, then authorizations, each created before one threshold.</summary>
	async Task RunAsync(TimeSpan minimumAge, CancellationToken stoppingToken)
	{
		// The per-run boundary is the one place a failure stops: a background loop has no caller to propagate to, and an
		// exception escaping ExecuteAsync stops the host (BackgroundServiceExceptionBehavior.StopHost). Every failure is
		// logged at Error with its exception and the next tick retries; cancellation of the host still propagates.
		try
		{
			var scope = scopeFactory.CreateAsyncScope();
			await using (scope.ConfigureAwait(false))
			{
				var services = scope.ServiceProvider;
				var threshold = timeProvider.GetUtcNow() - minimumAge;
				var tokens = await services.GetRequiredService<IOpenIddictTokenManager>().Outcome
					.PruneAsync(threshold, stoppingToken).ConfigureAwait(false);
				if (!Pruned(tokens, "tokens", out var tokenCount))
					return;

				var sessions = await services.GetRequiredService<IOpenIddictSessionManager>().Outcome
					.PruneAsync(threshold, stoppingToken).ConfigureAwait(false);
				if (!Pruned(sessions, "sessions", out var sessionCount))
					return;

				var authorizations = await services.GetRequiredService<IOpenIddictAuthorizationManager>().Outcome
					.PruneAsync(threshold, stoppingToken).ConfigureAwait(false);
				if (!Pruned(authorizations, "authorizations", out var authorizationCount))
					return;

				LogPruned(logger, tokenCount, sessionCount, authorizationCount, threshold);
			}
		}
		catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
		{
			LogFailed(logger, exception);
		}
	}

	/// <summary>Whether the step succeeded, logging the run's end when it did not.</summary>
	bool Pruned(Outcome<long> outcome, string step, out long count)
	{
		var failed = outcome.Match(static _ => (ErrorCategory?)null, static problem => problem.Category);
		count = outcome.Match(static value => value, static _ => 0L);
		if (failed is not { } category)
			return true;

		LogStepFailed(logger, step, category);
		return false;
	}

	[LoggerMessage(EventId = DisabledEventId, Level = LogLevel.Information,
		Message = "The OpenIddict pruner is disabled (Identity:OpenIddict:Pruning:Enabled is false).")]
	static partial void LogDisabled(ILogger logger);

	[LoggerMessage(EventId = RunEventId, Level = LogLevel.Information,
		Message = "Pruned {Tokens} token(s), {Sessions} session(s) and {Authorizations} authorization(s) created before {Threshold}.")]
	static partial void LogPruned(ILogger logger, long tokens, long sessions, long authorizations, DateTimeOffset threshold);

	[LoggerMessage(EventId = FailureEventId, Level = LogLevel.Error,
		Message = "The OpenIddict pruning run failed; the next run retries.")]
	static partial void LogFailed(ILogger logger, Exception exception);

	[LoggerMessage(EventId = StepFailedEventId, Level = LogLevel.Error,
		Message = "Pruning OpenIddict {Step} failed ({Category}); the run ended there and the next run retries.")]
	static partial void LogStepFailed(ILogger logger, string step, ErrorCategory category);
}
