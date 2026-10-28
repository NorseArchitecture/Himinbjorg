using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Passkeys;

/// <summary>
///     Removes one of the caller's passkeys in place, answering <see langword="true" />; the client renders its own
///     deleted text. An id that does not decode answers <see cref="CredentialIds.Invalid" /> and a passkey the caller
///     does not have <see cref="CredentialIds.NotFound" />, both before any write; the removal's failure passes through.
/// </summary>
/// <remarks>
///     No last-credential guard: a passkey is never an account's sole credential. Accounts are born with a password or
///     an external login, and removing an external login already ignores passkeys when it decides whether another
///     credential remains. A passkey-only account path must add the guard here.
/// </remarks>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="userManager">Reads and removes the passkey.</param>
sealed class RemovePasskeyHandler(AccountCaller caller, UserManager<NorseUser> userManager)
	: IRequestHandler<RemovePasskeyCommand, BoolResponse>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<BoolResponse>> Handle(RemovePasskeyCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> success);
		var user = success.Value;

		if (!CredentialIds.TryDecode(request.Request.CredentialId, out var credentialId))
			return new(CredentialIds.Invalid);

		if (await userManager.GetPasskeyAsync(user, credentialId).ConfigureAwait(false) is null)
			return new(CredentialIds.NotFound);

		var removed = await userManager.Outcome.RemovePasskeyAsync(user, credentialId, cancellationToken)
			.ConfigureAwait(false);
		if (removed.TryGetValue(out Failed removeFailed))
			return new(removeFailed);

		return Outcome<BoolResponse>.Ok(new BoolResponse { Value = true });
	}
}
