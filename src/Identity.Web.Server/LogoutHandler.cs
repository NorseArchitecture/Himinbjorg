using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server;

sealed class LogoutHandler(SignInManager<NorseUser> signInManager, IDeferredSignIn deferredSignIn, IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<LogoutCommand, LogoutResult>
{
	public async ValueTask<Outcome<LogoutResult>> Handle(LogoutCommand request, CancellationToken cancellationToken = default)
	{
		await signInManager.SignOutAsync().ConfigureAwait(false);
		return Outcome<LogoutResult>.Ok(new LogoutResult { DeferredCompletionUrl = TryGetDeferredCompletionUrl() });
	}

	// Duplicated verbatim in LoginHandler — Buvy's explicit call: no shared helper class for four
	// lines shared by exactly two handlers.
	string? TryGetDeferredCompletionUrl()
	{
		if (httpContextAccessor.HttpContext!.Items[NorseSignInManager.DeferredSignInKeyItemName] is not string key)
			return null;

		return deferredSignIn.BuildCompletionUrl(key, "/");
	}
}
