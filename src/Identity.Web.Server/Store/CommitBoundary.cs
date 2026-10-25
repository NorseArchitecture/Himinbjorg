using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity.Web.Server.Store;

/// <summary>
///     The commit of an explicit transaction, with its two outcomes kept apart (2026-10-24 explicit-writes spec §4.10).
///     A failure before the commit reaches the database is <b>definite</b>: nothing committed. A failure once it may
///     have reached it -- the commit's acknowledgement lost to a broken connection -- is <b>indeterminate</b>, and is
///     never guessed at and never retried.
/// </summary>
/// <remarks>
///     <para>
///         How a failed commit is told apart differs by provider, because the two answer a <c>ROLLBACK</c> after a
///         commit that landed differently.
///     </para>
///     <para>
///         <b>SQL Server</b> refuses it: a <c>ROLLBACK</c> with no open transaction raises error 3903 ("no
///         corresponding BEGIN TRANSACTION"), and SqlClient refuses a zombied transaction outright. A rollback the
///         database accepts therefore proves the transaction was still open, so the commit never landed: the rollback
///         probe is sound there.
///     </para>
///     <para>
///         <b>PostgreSQL</b> accepts it: a <c>ROLLBACK</c> with no transaction in progress is only a WARNING. If the
///         connection survives a commit that actually landed (a command timeout whose cancel arrived after the server
///         committed), the probe would be accepted and a landed commit called definite -- the dangerous direction. So
///         PostgreSQL asks the database instead: the transaction's id, captured with <c>pg_current_xact_id()</c>
///         before the commit, is looked up with <c>pg_xact_status</c> on a fresh connection. <c>committed</c> is
///         committed, <c>aborted</c> is definite, and <c>in progress</c>, null (wrapped around or too old) or a lookup
///         that fails is indeterminate. Where a <c>users</c> statement wrote a stamp marker, the marker decides
///         (<see cref="NorseUserStore" /> reads it on a fresh connection), so no id is captured and the failure is
///         handed over as indeterminate.
///     </para>
/// </remarks>
static class CommitBoundary
{
	/// <summary>
	///     Commits <paramref name="transaction" />, resolving a failed commit per provider (see the remarks). Nothing
	///     is ever retried: a failure resolved as committed returns normally, one resolved as never landed rethrows the
	///     original failure, and anything else throws <see cref="IndeterminateWriteException" />.
	/// </summary>
	/// <param name="context">The context <paramref name="transaction" /> belongs to.</param>
	/// <param name="transaction">The open transaction holding the operation's statements, all already executed.</param>
	/// <param name="markerDecides">
	///     Whether a stamp marker was written, so the caller resolves an indeterminate commit itself and PostgreSQL
	///     needs no transaction id.
	/// </param>
	/// <param name="operation">What the transaction writes, named in the indeterminate failure.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <exception cref="IndeterminateWriteException">The commit failed and may have taken effect.</exception>
	public static async Task CommitAsync(NorseIdentityDbContext context, IDbContextTransaction transaction, bool markerDecides,
		string operation, CancellationToken cancellationToken = default)
	{
		var sqlServer = context.Database.ProviderName == NorseDbContextOptionsExtensions.SqlServerProviderName;
		var xid = sqlServer || markerDecides ? null : await CurrentXidAsync(context, cancellationToken).ConfigureAwait(false);
		try
		{
			await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
		}
		catch (Exception failure)
		{
			switch (sqlServer ? await ProbedAsync(transaction).ConfigureAwait(false) : await AskedAsync(context, transaction, xid).ConfigureAwait(false))
			{
				case Landing.Never:
					throw;
				case Landing.Committed:
					return;
				default:
					throw new IndeterminateWriteException(
						$"The commit of {operation} failed after it was issued, so it may or may not have taken effect. Nothing retries it: re-read before acting.",
						failure);
			}
		}
	}

	/// <summary>A context of its own over <paramref name="context" />'s options, so on a fresh connection.</summary>
	/// <param name="context">The context whose options (interceptors included) the fresh one shares.</param>
	/// <returns>The fresh context, which the caller disposes.</returns>
	public static NorseIdentityDbContext Fresh(NorseIdentityDbContext context) =>
		new((DbContextOptions<NorseIdentityDbContext>)context.GetService<IDbContextOptions>());

	/// <summary>
	///     The PostgreSQL transaction's id, read inside it before the commit. Every caller has already written, so the
	///     read never forces an id onto a read-only transaction.
	/// </summary>
	static async Task<string?> CurrentXidAsync(NorseIdentityDbContext context, CancellationToken cancellationToken) =>
		await context.Database
			.SqlQueryRaw<string>("""SELECT pg_current_xact_id()::text AS "Value" """)
			.SingleAsync(cancellationToken)
			.ConfigureAwait(false);

	/// <summary>
	///     SQL Server: whether the database rolled the failed transaction back. Never cancelled: the answer decides the
	///     outcome. A completed transaction (error 3903) and a broken connection both refuse the rollback.
	/// </summary>
	static async Task<Landing> ProbedAsync(IDbContextTransaction transaction) =>
		await RolledBackAsync(transaction).ConfigureAwait(false) ? Landing.Never : Landing.Unknown;

	/// <summary>
	///     PostgreSQL: the failed transaction is rolled back if it can be (its answer proves nothing here), then its
	///     status is read on a fresh connection. Without a captured id the marker decides, so the answer is unknown.
	///     Never cancelled: the answer decides the outcome.
	/// </summary>
	static async Task<Landing> AskedAsync(NorseIdentityDbContext context, IDbContextTransaction transaction, string? xid)
	{
		await RolledBackAsync(transaction).ConfigureAwait(false);
		if (xid is null)
			return Landing.Unknown;

		var fresh = Fresh(context);
		await using (fresh.ConfigureAwait(false))
		{
			try
			{
				var status = await fresh.Database
					.SqlQuery<string>($"""SELECT pg_xact_status({xid}::xid8) AS "Value" """)
					.ToListAsync(CancellationToken.None)
					.ConfigureAwait(false);
				return status switch
				{
					["committed"] => Landing.Committed,
					["aborted"] => Landing.Never,
					_ => Landing.Unknown
				};
			}
			catch (Exception failure) when (failure is DbException or InvalidOperationException)
			{
				return Landing.Unknown;
			}
		}
	}

	/// <summary>Whether the database accepted the failed transaction's rollback. Never cancelled.</summary>
	static async Task<bool> RolledBackAsync(IDbContextTransaction transaction)
	{
		try
		{
			await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
			return true;
		}
		catch (Exception refused) when (refused is DbException or InvalidOperationException)
		{
			return false;
		}
	}

	/// <summary>What became of a commit that failed.</summary>
	enum Landing
	{
		/// <summary>Not known: indeterminate.</summary>
		Unknown = 0,

		/// <summary>It never landed: the failure is definite.</summary>
		Never = 1,

		/// <summary>It landed: the operation committed.</summary>
		Committed = 2
	}
}
