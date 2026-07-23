using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components;

namespace Norse.Identity.Web.Server;

sealed class LogoutHandler(SignInManager<NorseUser> signInManager)
	: IRequestHandler<LogoutRequest, Outcome>
{
	public async ValueTask<Outcome> Handle(LogoutRequest request, CancellationToken cancellationToken)
	{
		await signInManager.SignOutAsync().ConfigureAwait(false);
		return Outcome.Ok();
	}
}
