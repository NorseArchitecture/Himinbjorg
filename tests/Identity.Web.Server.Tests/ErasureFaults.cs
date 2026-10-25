using System.Data.Common;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     Decorates the fixture's real <see cref="ISubjectKeyStore" /> and fails <see cref="DestroyAsync" /> once, at the
///     chosen side of the real call. Midgard's own checkpoint seam is internal to Midgard; this decorator reaches
///     the two boundaries erasure sees from outside: the store failing before it destroys anything, and the store
///     destroying and then the caller losing the answer.
/// </summary>
/// <param name="inner">The real store every call delegates to.</param>
sealed class FaultingSubjectKeyStore(ISubjectKeyStore inner) : ISubjectKeyStore
{
	Exception? _failBeforeDestroy;
	Exception? _failAfterDestroy;
	int _destroyCalls;

	/// <summary>How many times <see cref="DestroyAsync" /> was called, failed calls included.</summary>
	public int DestroyCalls => Volatile.Read(ref _destroyCalls);

	/// <summary>Thrown by the next <see cref="DestroyAsync" /> instead of reaching the real store.</summary>
	public Exception? FailBeforeDestroy
	{
		init => _failBeforeDestroy = value;
	}

	/// <summary>Thrown by the next <see cref="DestroyAsync" /> after the real store has destroyed the key.</summary>
	public Exception? FailAfterDestroy
	{
		init => _failAfterDestroy = value;
	}

	public ValueTask<SubjectKeyResult> GetAsync(Guid subjectId, CancellationToken cancellationToken = default) =>
		inner.GetAsync(subjectId, cancellationToken);

	public ValueTask<byte[]> GetOrCreateAsync(Guid subjectId, CancellationToken cancellationToken = default) =>
		inner.GetOrCreateAsync(subjectId, cancellationToken);

	public async ValueTask<ErasureReceipt> DestroyAsync(Guid subjectId, CancellationToken cancellationToken = default)
	{
		Interlocked.Increment(ref _destroyCalls);
		if (Interlocked.Exchange(ref _failBeforeDestroy, null) is { } before)
			throw before;

		var receipt = await inner.DestroyAsync(subjectId, cancellationToken);
		return Interlocked.Exchange(ref _failAfterDestroy, null) is { } after ?
			throw after :
			receipt;
	}
}

/// <summary>Fails the first non-query command whose text contains <paramref name="marker" />, before it runs.</summary>
/// <param name="marker">A fragment of the command text, such as the delimited table name.</param>
sealed class FailingCommandInterceptor(string marker) : DbCommandInterceptor
{
	int _armed = 1;

	public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
		CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default) =>
		command.CommandText.Contains(marker, StringComparison.Ordinal) && Interlocked.Exchange(ref _armed, 0) == 1 ?
			throw new SimulatedDbException($"Simulated failure of a command against {marker}.") :
			ValueTask.FromResult(result);
}

/// <summary>A non-transient database failure: no execution strategy retries it.</summary>
/// <param name="message">The failure's description.</param>
sealed class SimulatedDbException(string message) : DbException(message);
