using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server;

sealed class RegisterHandler(UserManager<NorseUser> userManager)
	: IRequestHandler<RegisterCommand, RegisterResult>
{
	public async ValueTask<Outcome<RegisterResult>> Handle(RegisterCommand request, CancellationToken cancellationToken = default)
	{
		var wire = request.Request;
		NorseUser user = new() { UserName = wire.Email, Email = wire.Email };
		var result = await userManager.CreateAsync(user, wire.Password).ConfigureAwait(false);

		if (result.Succeeded)
			return Outcome<RegisterResult>.Ok(new RegisterResult { Succeeded = true });
		// Only a genuine duplicate is Conflict — Buvy's explicit call, so a legitimate user sees
		// "that email's taken" and doesn't retry a doomed registration 10,000 times (spec §9.3).
		// Everything else (password-policy codes) is Validation — a rejected password isn't a conflict.
		var isDuplicate = result.Errors.Any(e => e.Code is "DuplicateUserName" or "DuplicateEmail");
		var category = isDuplicate ? ErrorCategory.Conflict : ErrorCategory.Validation;
		var errors = result.Errors
			.GroupBy(e => e.Code)
			.ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray());
		return Outcome<RegisterResult>.Err(category, errors);
	}
}
