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

	/// <summary>Thrown by every <see cref="DestroyAsync" /> after the real store has destroyed the key.</summary>
	public Exception? FailEveryDestroy { get; init; }

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
		if (FailEveryDestroy is { } every)
			throw every;

		return Interlocked.Exchange(ref _failAfterDestroy, null) is { } after ?
			throw after :
			receipt;
	}
}

/// <summary>
///     Fails the first <paramref name="failures" /> non-query commands whose text contains <paramref name="marker" />, each
///     before it runs; every later one runs.
/// </summary>
/// <param name="marker">A fragment of the command text, such as the delimited table name.</param>
/// <param name="failures">How many matching commands fail.</param>
sealed class FailingCommandInterceptor(string marker, int failures = 1) : DbCommandInterceptor
{
	int _remaining = failures;
	int _fired;

	/// <summary>How many matching commands were failed.</summary>
	public int Fired => Volatile.Read(ref _fired);

	public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
		CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
	{
		if (!command.CommandText.Contains(marker, StringComparison.Ordinal) || Interlocked.Decrement(ref _remaining) < 0)
			return ValueTask.FromResult(result);

		Interlocked.Increment(ref _fired);
		throw new SimulatedDbException($"Simulated failure of a command against {marker}.");
	}
}

/// <summary>A non-transient database failure: no execution strategy retries it.</summary>
/// <param name="message">The failure's description.</param>
sealed class SimulatedDbException(string message) : DbException(message);
