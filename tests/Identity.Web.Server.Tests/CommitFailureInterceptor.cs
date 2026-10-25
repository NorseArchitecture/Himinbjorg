using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>Where a <see cref="CommitFailureInterceptor" /> fails the first commit it sees.</summary>
enum CommitFailure
{
	/// <summary>Not one of the modes: the interceptor only counts.</summary>
	None = 0,

	/// <summary>
	///     Before the commit is issued (<c>TransactionCommittingAsync</c>): nothing reaches the database, so the
	///     transaction is still open and the failure is definite.
	/// </summary>
	BeforeCommit = 1,

	/// <summary>
	///     After the commit landed (<c>TransactionCommittedAsync</c>): the database has the change and the caller loses
	///     the acknowledgement, the indeterminate case (2026-10-24 explicit-writes spec §4.10). The outage that lost the
	///     acknowledgement also hides the outcome: PostgreSQL's <c>pg_xact_status</c> lookup fails too.
	/// </summary>
	AfterCommit = 2,

	/// <summary>
	///     As <see cref="AfterCommit" />, but the database can still be asked: the <c>pg_xact_status</c> lookup
	///     succeeds and reports the transaction committed.
	/// </summary>
	AfterCommitOutcomeVisible = 3,

	/// <summary>
	///     The commit lands through the transaction's own connection, which survives, and then the failure surfaces
	///     anyway (a command timeout whose cancel arrived after the server committed). The client still believes the
	///     transaction open, so its rollback goes out as a plain <c>ROLLBACK</c> on that connection and is accepted:
	///     PostgreSQL only warns that no transaction is in progress.
	/// </summary>
	CommittedOnSurvivingConnection = 4
}

/// <summary>
///     The commit-outcome seam (2026-10-24 explicit-writes plan Task 4.9): fails the first commit of the context it is
///     attached to, at the side <paramref name="mode" /> names, and counts, so every test can assert the injection
///     really happened and that nothing committed again behind it. It also sees every command of every context built
///     from the same options, which is how <see cref="CommitFailure.AfterCommit" /> blinds the outcome lookup.
/// </summary>
/// <param name="mode">Where the first commit fails.</param>
/// <param name="afterCommit">
///     Runs after the commit landed and before the acknowledgement is lost, for a concurrent writer that must commit in
///     that window. Only in <see cref="CommitFailure.AfterCommit" /> mode.
/// </param>
sealed class CommitFailureInterceptor(CommitFailure mode, Func<CancellationToken, Task>? afterCommit = null) :
	DbTransactionInterceptor, IDbCommandInterceptor
{
	int _armed = 1;
	int _fired;
	int _commits;
	int _rollbacksAccepted;

	/// <summary>How many times the failure was injected: one, or the test proved nothing.</summary>
	public int Fired => Volatile.Read(ref _fired);

	/// <summary>How many commits the context attempted, the failed one included: no automatic replay means one.</summary>
	public int Commits => Volatile.Read(ref _commits);

	/// <summary>How many rollbacks the database accepted after the injection.</summary>
	public int RollbacksAccepted => Volatile.Read(ref _rollbacksAccepted);

	public override async ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction, TransactionEventData eventData,
		InterceptionResult result, CancellationToken cancellationToken = default)
	{
		Interlocked.Increment(ref _commits);
		if (mode is CommitFailure.BeforeCommit && Fire())
			throw new SimulatedDbException("Simulated failure before the commit was issued: the transaction is still open.");

		if (mode is not CommitFailure.CommittedOnSurvivingConnection || !Fire())
			return result;

		// Behind the client's back: the server commits, the connection stays open, the transaction object stays live.
		await using var commit = transaction.Connection!.CreateCommand();
		commit.Transaction = transaction;
		commit.CommandText = "COMMIT";
		await commit.ExecuteNonQueryAsync(cancellationToken);
		throw new SimulatedDbException("Simulated timeout of a commit that landed: the connection survived.");
	}

	public override async Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData eventData,
		CancellationToken cancellationToken = default)
	{
		if (mode is not (CommitFailure.AfterCommit or CommitFailure.AfterCommitOutcomeVisible) || !Fire())
			return;

		if (afterCommit is not null)
			await afterCommit(cancellationToken);

		throw new SimulatedDbException("Simulated loss of the commit's acknowledgement: the transaction committed.");
	}

	public override async ValueTask<InterceptionResult> TransactionRollingBackAsync(DbTransaction transaction, TransactionEventData eventData,
		InterceptionResult result, CancellationToken cancellationToken = default)
	{
		if (mode is not CommitFailure.CommittedOnSurvivingConnection || Fired is 0)
			return result;

		// The client never learned of the commit, so its rollback reaches the server as a plain ROLLBACK, which
		// PostgreSQL accepts with nothing but a "there is no transaction in progress" warning.
		await using var rollback = transaction.Connection!.CreateCommand();
		rollback.CommandText = "ROLLBACK";
		await rollback.ExecuteNonQueryAsync(cancellationToken);
		return InterceptionResult.Suppress();
	}

	public override Task TransactionRolledBackAsync(DbTransaction transaction, TransactionEndEventData eventData,
		CancellationToken cancellationToken = default)
	{
		if (Fired is not 0)
			Interlocked.Increment(ref _rollbacksAccepted);
		return Task.CompletedTask;
	}

	public ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData,
		InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default) =>
		mode is CommitFailure.AfterCommit && Fired is not 0 && command.CommandText.Contains("pg_xact_status", StringComparison.Ordinal) ?
			throw new SimulatedDbException("Simulated outage: the commit's outcome can't be looked up either.") :
			ValueTask.FromResult(result);

	bool Fire()
	{
		if (Interlocked.Exchange(ref _armed, 0) is not 1)
			return false;

		Interlocked.Increment(ref _fired);
		return true;
	}
}
