using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components.Shared;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Passkeys;

/// <summary>
///     Renames one of the caller's passkeys and answers the passkeys page with
///     <see cref="ManageStatus.PasskeyUpdated" /> (a soft navigation; nothing here writes a cookie). An id that does not
///     decode answers <see cref="CredentialIds.Invalid" /> and a passkey the caller does not have
///     <see cref="CredentialIds.NotFound" />, both before any write; the save's failure passes through.
/// </summary>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="userManager">Reads and saves the passkey.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
sealed class RenamePasskeyHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<RenamePasskeyCommand, NavigationResult>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(RenamePasskeyCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> success);
		var user = success.Value;

		if (!CredentialIds.TryDecode(request.Request.CredentialId, out var credentialId))
			return new(CredentialIds.Invalid);

		var passkey = await userManager.GetPasskeyAsync(user, credentialId).ConfigureAwait(false);
		if (passkey is null)
			return new(CredentialIds.NotFound);

		passkey.Name = request.Request.Name;
		var saved = await userManager.Outcome.AddOrUpdatePasskeyAsync(user, passkey, cancellationToken)
			.ConfigureAwait(false);
		if (saved.TryGetValue(out Failed saveFailed))
			return new(saveFailed);

		return Outcome<NavigationResult>.Ok(new NavigationResult
		{
			NextUrl = ManageUrls.Status(httpContextAccessor.HttpContext!.Request.PathBase, "/Account/Manage/Passkeys",
				ManageStatus.PasskeyUpdated)
		});
	}
}
