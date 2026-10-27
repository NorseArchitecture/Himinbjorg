using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server;

sealed class LogoutHandler(
	SignInManager<NorseUser> signInManager,
	DeferredCompletion deferredCompletion)
	: IRequestHandler<LogoutCommand, NavigationResult>
{
	public async ValueTask<Outcome<NavigationResult>> Handle(LogoutCommand request,
		CancellationToken cancellationToken = default)
	{
		await signInManager.SignOutAsync().ConfigureAwait(false);
		// The deferred-completion detour (circuit path) or the app root — either way one concrete,
		// server-resolved hop; the client's null-branch is gone with the old wire shape.
		return Outcome<NavigationResult>.Ok(new NavigationResult { NextUrl = deferredCompletion.TryBuildUrl("/") ?? "/" });
	}
}
