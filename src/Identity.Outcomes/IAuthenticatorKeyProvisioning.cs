using Microsoft.AspNetCore.Identity;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Outcomes;

/// <summary>
///     A lossless authenticator-key provisioning: the stored key when there is one, otherwise a new key and the update's
///     own <see cref="IdentityResult" /> beside it, where <see cref="UserManager{TUser}.ResetAuthenticatorKeyAsync" />
///     rotates the security stamp and the setup page's read-then-reset loses the write's outcome. Idempotent, so the
///     setup page's double load (prerender, then interactive) provisions once, and race-safe: over the explicit-writes
///     store the first write is conditional (insert-if-absent), so concurrent first setups all answer the one key
///     stored, never each their own with the last writer winning. Implemented by <c>NorseUserManager</c>;
///     Norse callers reach it through <see cref="UserManagerOutcomeView.ProvisionAuthenticatorKeyAsync" />.
/// </summary>
public interface IAuthenticatorKeyProvisioning
{
	/// <summary>
	///     Answers <paramref name="user" />'s authenticator key, storing a new one, without rotating the security stamp,
	///     when there is none.
	/// </summary>
	/// <param name="user">The user whose key to provision.</param>
	/// <returns>
	///     <see cref="IdentityResult.Success" /> and the stored key with no write, or the update's result, untouched,
	///     and, on success, the key stored after it (this call's, or a concurrent setup's that landed first).
	/// </returns>
	Task<(IdentityResult Result, string Key)> ProvisionAuthenticatorKeyAsync(NorseUser user);
}
