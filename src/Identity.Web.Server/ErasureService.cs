using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Store;

namespace Norse.Identity.Web.Server;

/// <summary>
///     Erasure as a hard delete, key first (2026-10-24 explicit-writes spec §7, superseding the 2026-08-03 PII
///     spec's darken-in-place ceremony). Every run that returns <c>Ok</c> performs every step, and every step is
///     idempotent: probe the subject's key; destroy it unconditionally unless it is <c>Missing</c>; then, in one
///     database transaction, delete the subject's OpenIddict tokens and authorizations and the <c>users</c> row,
///     whose cascade removes every child table. Whether the row exists proves nothing about completion, so no
///     step is skipped because a previous run got further.
/// </summary>
/// <remarks>
///     <para>
///         <b>Retry until <c>Ok</c> is the caller's obligation</b> (recorded as the future DSAR machinery's
///         contract). A run that fails anywhere answers <see cref="ErrorCategory.Fault" /> and leaves a state the
///         next run finishes: a failure before or during destruction leaves the key intact or its receipt
///         pending, which the next <see cref="ISubjectKeyStore.DestroyAsync" /> completes; a failure after it
///         leaves the rows intact behind a destroyed key (reads answer <see cref="KeyDestroyedException" />,
///         spec §5), which the next transaction deletes; a failure after commit leaves nothing to do, and the
///         next run returns the same receipt. A commit whose acknowledgement is lost answers
///         <see cref="ErrorCategory.Indeterminate" /> instead (spec §4.10): <c>Fault</c> would claim no effect, and the
///         rows may already be gone. It is never retried, and re-running is safe either way, since every delete is
///         idempotent (spec §7.3). The key store is linearizable per subject, so concurrent runs
///         return one authoritative receipt; the deletes are by id and carry no concurrency obligation of their
///         own.
///     </para>
///     <para>
///         The <c>users</c> delete is raw SQL named from the model: <c>ExecuteDelete</c> is refused for a split
///         entity, and the row's foreign keys cascade to <c>user_credentials</c> and the other child tables. Both
///         deletes bypass the change tracker, so a <see cref="NorseUser" /> still tracked in the same scope is
///         stale afterward; saving it fails on the missing row rather than restoring it.
///     </para>
/// </remarks>
/// <param name="context">The identity context the deletes run through.</param>
/// <param name="keyStore">The external store holding the subject's key; no database transaction includes it.</param>
/// <param name="logger">Records every fault, since the outcome carries only its category.</param>
public sealed partial class ErasureService(
	NorseIdentityDbContext context,
	ISubjectKeyStore keyStore,
	ILogger<ErasureService> logger)
{
	/// <summary>Erases the subject, or finishes an erasure a previous run left incomplete.</summary>
	/// <param name="subjectId">The user id, which is also the subject id the key store and OpenIddict carry.</param>
	/// <param name="cancellationToken">Cancels the run; cancellation propagates rather than folding to a fault.</param>
	/// <returns>
	///     The one authoritative receipt; <see cref="ErrorCategory.NotFound" /> when neither a key nor a row exists,
	///     with nothing written; <see cref="ErrorCategory.Indeterminate" /> when the transaction's commit may or may
	///     not have landed; otherwise <see cref="ErrorCategory.Fault" />. A retry resolves both failures, unless the
	///     subject has a row but no key (an incident, not an erasure).
	/// </returns>
	public async Task<Outcome<ErasureReceipt>> ShredAsync(Guid subjectId, CancellationToken cancellationToken = default)
	{
		try
		{
			var probe = await keyStore.GetAsync(subjectId, cancellationToken).ConfigureAwait(false);
			if (probe.Match(static _ => false, static _ => false, static () => true))
				return await MissingKeyAsync(subjectId, cancellationToken).ConfigureAwait(false);

			var receipt = await keyStore.DestroyAsync(subjectId, cancellationToken).ConfigureAwait(false);
			await context.Database
				.CreateExecutionStrategy()
				.ExecuteAsync(subjectId, DeleteSubjectRowsAsync, cancellationToken)
				.ConfigureAwait(false);
			return Outcome<ErasureReceipt>.Ok(receipt);
		}
		catch (IndeterminateWriteException exception)
		{
			LogShredIndeterminate(logger, subjectId, exception);
			return Outcome<ErasureReceipt>.Err(ErrorCategory.Indeterminate);
		}
		catch (Exception exception) when (IsInfrastructureFailure(exception))
		{
			LogShredFailed(logger, subjectId, exception);
			return Outcome<ErasureReceipt>.Err(ErrorCategory.Fault);
		}
	}

	/// <summary>
	///     <see cref="ShredAsync" />, re-run while it answers <see cref="ErrorCategory.Fault" /> or
	///     <see cref="ErrorCategory.Indeterminate" />, for a caller that cannot come back: once the key is destroyed,
	///     the account can no longer be materialized and its session dies at the next revalidation, so a self-service
	///     erasure gets no second request to retry from (PR #76 review). Re-running is safe at every boundary, since
	///     every step is idempotent (spec §7.3). An outcome still failing after the last attempt is logged by the run
	///     that produced it and is an operator's to finish.
	/// </summary>
	/// <param name="subjectId">The user id, which is also the subject id the key store and OpenIddict carry.</param>
	/// <param name="attempts">The most runs to make, at least one.</param>
	/// <param name="cancellationToken">Cancels the runs; cancellation propagates rather than folding to a fault.</param>
	/// <returns>The first settled outcome, or the last attempt's failure.</returns>
	public async Task<Outcome<ErasureReceipt>> ShredWithRetriesAsync(Guid subjectId, int attempts,
		CancellationToken cancellationToken = default)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(attempts, 1);
		Outcome<ErasureReceipt> outcome;
		var attempt = 0;
		do
			outcome = await ShredAsync(subjectId, cancellationToken).ConfigureAwait(false);
		while (++attempt < attempts && outcome.Match(static _ => false,
			static problem => problem.Category is ErrorCategory.Fault or ErrorCategory.Indeterminate));
		return outcome;
	}

	/// <summary>
	///     The failures a retry can resolve, or that only an operator can: lock exhaustion
	///     (<see cref="TimeoutException" />, spec §7.5), the key store's file or vault I/O, a key that vanished
	///     with no receipt (<see cref="KeyMissingException" />), and the database, directly or after the
	///     execution strategy exhausts its retries. Cancellation and programming errors propagate.
	/// </summary>
	static bool IsInfrastructureFailure(Exception exception) =>
		exception is TimeoutException or IOException or KeyMissingException or DbException
			or RetryLimitExceededException;

	/// <summary>No key and no receipt: <c>NotFound</c> for a ghost, burning nothing; a fault for a real row.</summary>
	async Task<Outcome<ErasureReceipt>> MissingKeyAsync(Guid subjectId, CancellationToken cancellationToken)
	{
		if (!await context.Users.AnyAsync(u => u.Id == subjectId, cancellationToken).ConfigureAwait(false))
			return Outcome<ErasureReceipt>.Err(ErrorCategory.NotFound);

		LogKeyMissing(logger, subjectId);
		return Outcome<ErasureReceipt>.Err(ErrorCategory.Fault);
	}

	/// <summary>
	///     The transaction (spec §7.2): the subject's OpenIddict tokens, including any under one of its
	///     authorizations, then its authorizations, then the <c>users</c> row. No foreign key reaches the
	///     OpenIddict rows from <c>users</c>, so they are deleted by subject; both deletes are idempotent.
	/// </summary>
	async Task DeleteSubjectRowsAsync(Guid subjectId, CancellationToken cancellationToken)
	{
		var subject = subjectId.ToString();
		var transaction = await context.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
		await using (transaction.ConfigureAwait(false))
		{
			var authorizationIds = context.Set<NorseOpenIddictAuthorization>()
				.Where(a => a.Subject == subject)
				.Select(a => (Guid?)a.Id);
			await context.Set<NorseOpenIddictToken>()
				.Where(t => t.Subject == subject || authorizationIds.Contains(t.AuthorizationId))
				.ExecuteDeleteAsync(cancellationToken)
				.ConfigureAwait(false);
			await context.Set<NorseOpenIddictAuthorization>()
				.Where(a => a.Subject == subject)
				.ExecuteDeleteAsync(cancellationToken)
				.ConfigureAwait(false);
			await context.Database
				.ExecuteSqlRawAsync(DeleteUserSql(), [subjectId], cancellationToken)
				.ConfigureAwait(false);
			await CommitBoundary.CommitAsync(context, transaction, false, $"the erasure of subject {subjectId}", cancellationToken).ConfigureAwait(false);
		}
	}

	/// <summary>
	///     <c>DELETE FROM users WHERE id = {0}</c>, with the table, schema and column the provider's naming
	///     conventions gave them, delimited by the provider's own helper.
	/// </summary>
	string DeleteUserSql()
	{
		var users = context.Users.EntityType;
		var tableName = users.GetTableName() ??
			throw new InvalidOperationException($"{nameof(NorseUser)} is not mapped to a table.");
		var schema = users.GetSchema();
		var idColumn = users.GetProperty(nameof(NorseUser.Id))
				.GetColumnName(StoreObjectIdentifier.Table(tableName, schema)) ??
			throw new InvalidOperationException($"{nameof(NorseUser)}.{nameof(NorseUser.Id)} has no column.");
		var sql = context.GetService<ISqlGenerationHelper>();
		return $"DELETE FROM {sql.DelimitIdentifier(tableName, schema)} WHERE {sql.DelimitIdentifier(idColumn)} = {{0}}";
	}

	[LoggerMessage(Level = LogLevel.Error,
		Message = "Erasing subject {SubjectId} failed; the erasure is incomplete until a retry returns its receipt.")]
	static partial void LogShredFailed(ILogger logger, Guid subjectId, Exception exception);

	[LoggerMessage(Level = LogLevel.Error,
		Message = "Erasing subject {SubjectId} may or may not have committed; the erasure is unconfirmed until a retry returns its receipt.")]
	static partial void LogShredIndeterminate(ILogger logger, Guid subjectId, Exception exception);

	[LoggerMessage(Level = LogLevel.Error,
		Message = "Subject {SubjectId} has an identity row but no key and no receipt: an incident, not an erasure.")]
	static partial void LogKeyMissing(ILogger logger, Guid subjectId);
}
