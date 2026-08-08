using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server;

sealed class LogoutHandler(SignInManager<NorseUser> signInManager, IDeferredSignIn deferredSignIn, IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<LogoutCommand, NavigationResult>
{
	public async ValueTask<Outcome<NavigationResult>> Handle(LogoutCommand request, CancellationToken cancellationToken = default)
	{
		await signInManager.SignOutAsync().ConfigureAwait(false);
		// The deferred-completion detour (circuit path) or the app root — either way one concrete,
		// server-resolved hop; the client's null-branch is gone with the old wire shape.
		return Outcome<NavigationResult>.Ok(new NavigationResult { NextUrl = TryGetDeferredCompletionUrl() ?? "/" });
	}

	// Was duplicated verbatim in LoginHandler; no longer is — LoginHandler's copy grew a returnUrl
	// parameter once Login gained a second destination (a completed sign-in vs. the 2FA challenge) that
	// can each need the deferred-completion detour. Logout only ever lands back on "/", so this stays
	// the original bare, parameterless shape — Buvy's explicit call: no shared helper class just to
	// reunify four lines that no longer match anyway.
	string? TryGetDeferredCompletionUrl()
	{
		if (httpContextAccessor.HttpContext!.Items[NorseSignInManager.DeferredSignInKeyItemName] is not string key)
			return null;

		return deferredSignIn.BuildCompletionUrl(key, "/");
	}
}
