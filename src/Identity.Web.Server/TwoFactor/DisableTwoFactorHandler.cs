using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components.Shared;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.TwoFactor;

/// <summary>
///     Disables two-factor authentication. A caller with it already off is refused and nothing is written. The disable
///     rotates the stamp, so the sign-in is refreshed and the answer is the two-factor page with
///     <see cref="ManageStatus.TwoFactorDisabled" />.
/// </summary>
/// <remarks>
///     T3-35: an indeterminate disable re-reads and refreshes through <see cref="AccountCaller.RefreshFromReReadAsync" />
///     and lands on the two-factor page with no status key, which shows the truth on load. A definite failure
///     refreshes nothing and passes through; the disable is the only write, so no later step can fail behind it.
/// </remarks>
/// <param name="caller">Resolves the calling user from the principal, and re-reads it after an indeterminate disable.</param>
/// <param name="userManager">Reads and clears the two-factor flag.</param>
/// <param name="signInManager">Refreshes the caller's sign-in after the stamp rotation.</param>
/// <param name="deferredCompletion">Builds the completion detour for whatever the refresh stashed.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
sealed class DisableTwoFactorHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	SignInManager<NorseUser> signInManager,
	DeferredCompletion deferredCompletion,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<DisableTwoFactorCommand, NavigationResult>
{
	const string TwoFactorRoute = "/Account/Manage/TwoFactorAuthentication";

	static readonly Failed _notEnabled =
		new(Problem.ModelError(ErrorCategory.Validation, "Two-factor authentication is not enabled."));

	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(DisableTwoFactorCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> success);
		var user = success.Value;

		if (!await userManager.GetTwoFactorEnabledAsync(user).ConfigureAwait(false))
			return new(_notEnabled);

		var pathBase = httpContextAccessor.HttpContext!.Request.PathBase;
		var disabled = await userManager.Outcome.SetTwoFactorEnabledAsync(user, false, cancellationToken).ConfigureAwait(false);
		if (disabled.TryGetValue(out Failed failed))
			return failed.Problem.Category is ErrorCategory.Indeterminate ?
				await caller.RefreshFromReReadAsync(signInManager, deferredCompletion,
					UriHelper.BuildRelative(pathBase, TwoFactorRoute), cancellationToken).ConfigureAwait(false) :
				new(failed);

		await signInManager.RefreshSignInAsync(user).ConfigureAwait(false);
		var url = ManageUrls.Status(pathBase, TwoFactorRoute, ManageStatus.TwoFactorDisabled);
		return Outcome<NavigationResult>.Ok(new NavigationResult { NextUrl = deferredCompletion.TryBuildUrl(url) ?? url });
	}
}
