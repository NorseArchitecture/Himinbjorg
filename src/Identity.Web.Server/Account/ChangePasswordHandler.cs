using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components.Shared;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Account;

/// <summary>
///     Changes the caller's password. A failure keeps everything the view's map attached -- category, correlation
///     id, an erasure receipt -- and only has its errors regrouped onto the wire fields
///     (<see cref="IdentityErrorFields.ForPasswordChange" />), so a mismatch lands on the current password and every
///     rule on the new one. The change rotates the security stamp, so the sign-in is refreshed and the answer is the
///     change-password page with the <see cref="ManageStatus.PasswordChanged" /> key, through the deferred-completion
///     detour on a circuit. The fold's failures pass through unchanged.
/// </summary>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="userManager">Changes the password.</param>
/// <param name="signInManager">Refreshes the caller's sign-in after the stamp rotation.</param>
/// <param name="deferredCompletion">Builds the completion detour for whatever the refresh stashed.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
sealed class ChangePasswordHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	SignInManager<NorseUser> signInManager,
	DeferredCompletion deferredCompletion,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<ChangePasswordCommand, NavigationResult>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(ChangePasswordCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> user);

		var wire = request.Request;
		var changed = await userManager.Outcome
			.ChangePasswordAsync(user.Value, wire.OldPassword, wire.NewPassword, cancellationToken)
			.ConfigureAwait(false);
		if (changed.TryGetValue(out Failed failed))
			return new(new Failed(failed.Problem with
			{
				Errors = IdentityErrorFields.Regroup(failed.Problem.Errors, IdentityErrorFields.ForPasswordChange)
			}));

		await signInManager.RefreshSignInAsync(user.Value).ConfigureAwait(false);
		var url = ManageUrls.Status(httpContextAccessor.HttpContext!.Request.PathBase, "/Account/Manage/ChangePassword",
			ManageStatus.PasswordChanged);
		return Outcome<NavigationResult>.Ok(new NavigationResult { NextUrl = deferredCompletion.TryBuildUrl(url) ?? url });
	}
}
