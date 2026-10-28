using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The consumed-challenge ledger's test double: refuses a state whose hash it has already seen, and records every
///     consumption it was asked for, so a handler test can tell what was consumed and with which expiry. It hashes the
///     raw state as the real ledger does (P5), so a caller that pre-hashes would be caught by the bytes it records.
/// </summary>
sealed class InMemoryPasskeyChallengeLedger : IPasskeyChallengeLedger
{
	readonly ConcurrentDictionary<string, DateTimeOffset> _consumed = new(StringComparer.Ordinal);
	readonly ConcurrentQueue<(byte[] State, DateTimeOffset ExpiresAt)> _requests = new();

	/// <summary>Every consumption asked for, in order: the raw state bytes and the expiry.</summary>
	public IReadOnlyList<(byte[] State, DateTimeOffset ExpiresAt)> Requests => [.. _requests];

	/// <inheritdoc />
	public ValueTask<bool> TryConsumeAsync(ReadOnlyMemory<byte> stateBytes, DateTimeOffset expiresAt,
		CancellationToken cancellationToken = default)
	{
		_requests.Enqueue((stateBytes.ToArray(), expiresAt));
		return ValueTask.FromResult(_consumed.TryAdd(Convert.ToHexString(SHA256.HashData(stateBytes.Span)), expiresAt));
	}
}
