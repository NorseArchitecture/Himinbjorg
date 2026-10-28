using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Passkeys;

/// <summary>
///     Answers one of the caller's passkeys in place, the rename page's pre-fill (T3-17). An id that does not decode
///     answers <see cref="CredentialIds.Invalid" /> before anything is read, and a passkey the caller does not have
///     <see cref="ErrorCategory.NotFound" />.
/// </summary>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="userManager">Reads the passkey.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
sealed class GetPasskeyHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<GetPasskeyCommand, PasskeyEntry>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<PasskeyEntry>> Handle(GetPasskeyCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> user);

		if (!CredentialIds.TryDecode(request.Request.CredentialId, out var credentialId))
			return new(CredentialIds.Invalid);

		var passkey = await userManager.GetPasskeyAsync(user.Value, credentialId).ConfigureAwait(false);
		return passkey is null ?
			new(CredentialIds.NotFound) :
			Outcome<PasskeyEntry>.Ok(CredentialIds.Entry(httpContextAccessor.HttpContext!.Request.PathBase, passkey));
	}
}
