using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server;

sealed class EmailExistsHandler(UserManager<NorseUser> userManager)
	: IRequestHandler<EmailExistsCommand, BoolResponse>
{
	public async ValueTask<Outcome<BoolResponse>> Handle(EmailExistsCommand request, CancellationToken cancellationToken = default)
	{
		var user = await userManager.FindByEmailAsync(request.Request.Email).ConfigureAwait(false);
		return Outcome<BoolResponse>.Ok(new BoolResponse { Value = user is not null });
	}
}
