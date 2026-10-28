namespace Norse.Identity.Web.Server;

/// <summary>
///     The consumed-challenge ledger (T3-32): a nonce ledger that lets a sealed, time-limited state be redeemed once.
///     Not passkey-specific despite its name: passkey sign-in (Task 4.10) burns its assertion state here, and the
///     recovery-codes handoff reveal burns its handoff. The ledger hashes the state itself (SHA-256), so callers pass
///     the raw unprotected bytes, never a hash of their own. Public only because the public
///     <see cref="NorseSignInManager" /> takes it by injection; its one implementation stays internal.
/// </summary>
public interface IPasskeyChallengeLedger
{
	/// <summary>
	///     Records <paramref name="stateBytes" /> as consumed, unless it already was. A consumption is kept until
	///     <paramref name="expiresAt" />, past which the state's own protector refuses it anyway.
	/// </summary>
	/// <param name="stateBytes">The raw, unprotected state.</param>
	/// <param name="expiresAt">The state's own expiry.</param>
	/// <param name="cancellationToken">Cancels the consumption.</param>
	/// <returns><see langword="true" /> for the first consumption; <see langword="false" /> for a replay.</returns>
	ValueTask<bool> TryConsumeAsync(ReadOnlyMemory<byte> stateBytes, DateTimeOffset expiresAt,
		CancellationToken cancellationToken = default);
}
