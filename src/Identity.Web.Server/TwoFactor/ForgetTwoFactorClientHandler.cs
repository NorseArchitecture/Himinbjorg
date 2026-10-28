using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components.Shared;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;

namespace Norse.Identity.Web.Server.TwoFactor;

/// <summary>
///     Forgets the calling machine, so the second factor is asked for again, and answers the two-factor page with
///     <see cref="ManageStatus.BrowserForgotten" />. On a circuit <see cref="NorseSignInManager" /> stashes the
///     remember-machine cookie's delete, so the answer rides the deferred completion that performs it.
/// </summary>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="signInManager">Forgets the client.</param>
/// <param name="deferredCompletion">Builds the completion detour for the stashed cookie delete.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
sealed class ForgetTwoFactorClientHandler(
	AccountCaller caller,
	SignInManager<NorseUser> signInManager,
	DeferredCompletion deferredCompletion,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<ForgetTwoFactorClientCommand, NavigationResult>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(ForgetTwoFactorClientCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);

		await signInManager.ForgetTwoFactorClientAsync().ConfigureAwait(false);
		var url = ManageUrls.Status(httpContextAccessor.HttpContext!.Request.PathBase,
			"/Account/Manage/TwoFactorAuthentication", ManageStatus.BrowserForgotten);
		return Outcome<NavigationResult>.Ok(new NavigationResult { NextUrl = deferredCompletion.TryBuildUrl(url) ?? url });
	}
}
