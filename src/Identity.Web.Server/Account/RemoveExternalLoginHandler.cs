using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components.Shared;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Account;

/// <summary>
///     Removes one of the caller's external logins. The store refuses removing the last sign-in method under the row
///     lock (<see cref="NorseIdentityErrorCodes.LastSignInMethod" />, answered as <see cref="ErrorCategory.Conflict" />),
///     so this handler keeps no count of its own (§5.9); that refusal and every other failure pass through unchanged.
///     The removal rotates the security stamp, so the sign-in is refreshed and the answer is the external-logins page
///     with the <see cref="ManageStatus.ExternalLoginRemoved" /> key, through the deferred-completion detour on a
///     circuit.
/// </summary>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="userManager">Removes the login.</param>
/// <param name="signInManager">Refreshes the caller's sign-in after the stamp rotation.</param>
/// <param name="deferredCompletion">Builds the completion detour for whatever the refresh stashed.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
sealed class RemoveExternalLoginHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	SignInManager<NorseUser> signInManager,
	DeferredCompletion deferredCompletion,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<RemoveExternalLoginCommand, NavigationResult>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(RemoveExternalLoginCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> user);

		var wire = request.Request;
		var removed = await userManager.Outcome
			.RemoveLoginAsync(user.Value, wire.LoginProvider, wire.ProviderKey, cancellationToken)
			.ConfigureAwait(false);
		if (removed.TryGetValue(out Failed failed))
			return new(failed);

		await signInManager.RefreshSignInAsync(user.Value).ConfigureAwait(false);
		var url = ManageUrls.Status(httpContextAccessor.HttpContext!.Request.PathBase, "/Account/Manage/ExternalLogins",
			ManageStatus.ExternalLoginRemoved);
		return Outcome<NavigationResult>.Ok(new NavigationResult { NextUrl = deferredCompletion.TryBuildUrl(url) ?? url });
	}
}
