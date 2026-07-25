using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server;

sealed class LogoutHandler(SignInManager<NorseUser> signInManager)
	: IRequestHandler<LogoutRequest, Outcome<Unit>>
{
	public async ValueTask<Outcome<Unit>> Handle(LogoutRequest request, CancellationToken cancellationToken)
	{
		await signInManager.SignOutAsync().ConfigureAwait(false);
		return Outcome<Unit>.Ok(Unit.Value);
	}
}
