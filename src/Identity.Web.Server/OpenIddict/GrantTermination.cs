using System.Diagnostics.Metrics;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using OpenIddict.Abstractions;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     <c>EndGrant(authorizationId)</c> (2026-10-29 OpenIddict spec §5.5): step 1 sets the authorization to <c>revoked</c>
///     (<see cref="GrantStatements.RevokeAuthorizationAsync" />), the durable boundary, in up to
///     <see cref="Attempts" /> attempts; step 2 revokes its tokens through <c>tokenManager.Outcome</c>, only after step 1 is
///     confirmed, as hygiene pruning would otherwise do.
/// </summary>
/// <remarks>
///     <para>
///         Step 1 is idempotent, so it is retried: any row count, zero for an authorization already revoked included, is a
///         definite success, and any exception is a failed attempt, never classified further. Every attempt failing is
///         <see cref="GrantEnd.Unconfirmed" />: an Error naming the authorization only (<c>GrantEndUnconfirmed</c>) and one
///         <c>norse.identity.grant_end_unconfirmed</c>, the one residual window, surfaced. The caller still refuses the
///         presented grant either way.
///     </para>
///     <para>
///         Step 1 ignores the caller's cancellation: the caller is a token or revocation request, and a client that hangs up
///         mid-reuse must not be the one who decides that its grant survives. Step 2 honors it. A failed step 2 logs a
///         Warning and still answers <see cref="GrantEnd.Confirmed" />: no token of a revoked authorization redeems.
///     </para>
/// </remarks>
/// <param name="context">The request's identity context, which step 1's statement runs on.</param>
/// <param name="tokens">The token manager, reached only through its <c>.Outcome</c> view.</param>
/// <param name="logger">The logger.</param>
/// <param name="meterFactory">Creates the <c>Norse.Identity</c> meter.</param>
sealed partial class GrantTermination(NorseIdentityDbContext context, IOpenIddictTokenManager tokens,
	ILogger<GrantTermination> logger, IMeterFactory meterFactory) : IGrantTermination
{
	/// <summary>The meter the counter is published on, the realm's one.</summary>
	internal const string MeterName = "Norse.Identity";

	/// <summary>The counter of grant ends that were never confirmed.</summary>
	internal const string UnconfirmedCounterName = "norse.identity.grant_end_unconfirmed";

	/// <summary>The event id of the Error an unconfirmed grant end logs.</summary>
	internal const int UnconfirmedEventId = 1;

	/// <summary>The event id of the Warning a failed step 2 logs.</summary>
	internal const int TokensNotRevokedEventId = 2;

	/// <summary>The event id of the Debug each failed step 1 attempt logs.</summary>
	internal const int AttemptFailedEventId = 3;

	/// <summary>How many times step 1 is attempted before the end is unconfirmed.</summary>
	internal const int Attempts = 3;

	readonly Counter<long> _unconfirmed = meterFactory.Create(MeterName).CreateCounter<long>(UnconfirmedCounterName,
		"{grant}", "Grant ends whose authorization revocation failed on every attempt (2026-10-29 OpenIddict spec §5.5).");

	/// <inheritdoc />
	public async Task<GrantEnd> EndAsync(Guid authorizationId, CancellationToken cancellationToken)
	{
		if (!await RevokeAuthorizationAsync(authorizationId).ConfigureAwait(false))
		{
			LogGrantEndUnconfirmed(logger, authorizationId);
			_unconfirmed.Add(1);
			return GrantEnd.Unconfirmed;
		}

		try
		{
			var revoked = await tokens.Outcome
				.RevokeByAuthorizationIdAsync(authorizationId.ToString(), cancellationToken)
				.ConfigureAwait(false);
			if (!revoked.Match(static _ => true, static _ => false))
				LogTokensNotRevoked(logger, authorizationId, null);
		}
		// Hygiene only, past a durable boundary: no failure here may turn the caller's refusal into a 500.
		catch (Exception exception) when (exception is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
		{
			LogTokensNotRevoked(logger, authorizationId, exception);
		}

		return GrantEnd.Confirmed;
	}

	/// <summary>Step 1: whether some attempt was a definite success.</summary>
	async Task<bool> RevokeAuthorizationAsync(Guid authorizationId)
	{
		for (var attempt = 1; attempt <= Attempts; attempt++)
			try
			{
				await GrantStatements.RevokeAuthorizationAsync(context, authorizationId, CancellationToken.None).ConfigureAwait(false);
				return true;
			}
			// Any exception is a failed attempt: a definite failure and a lost acknowledgement alike, since the statement is
			// idempotent and the next attempt settles both.
			catch (Exception exception)
			{
				LogAttemptFailed(logger, authorizationId, attempt, exception);
			}

		return false;
	}

	[LoggerMessage(EventId = UnconfirmedEventId, EventName = "GrantEndUnconfirmed", Level = LogLevel.Error,
		Message = "Ending the grant of authorization {AuthorizationId} was not confirmed: its revocation failed on every attempt.")]
	static partial void LogGrantEndUnconfirmed(ILogger logger, Guid authorizationId);

	[LoggerMessage(EventId = TokensNotRevokedEventId, Level = LogLevel.Warning,
		Message = "Authorization {AuthorizationId} is revoked, but revoking its tokens failed; none of them can be redeemed.")]
	static partial void LogTokensNotRevoked(ILogger logger, Guid authorizationId, Exception? exception);

	[LoggerMessage(EventId = AttemptFailedEventId, Level = LogLevel.Debug,
		Message = "Attempt {Attempt} to revoke authorization {AuthorizationId} failed.")]
	static partial void LogAttemptFailed(ILogger logger, Guid authorizationId, int attempt, Exception exception);
}
