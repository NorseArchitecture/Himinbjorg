using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components;

namespace Norse.Identity.Web.Server;

sealed class RegisterHandler(UserManager<NorseUser> userManager, RegisterRequestValidator validator)
	: IRequestHandler<RegisterRequest, Outcome<BoolResponse>>
{
	public async ValueTask<Outcome<BoolResponse>> Handle(RegisterRequest request, CancellationToken cancellationToken)
	{
		var validation = await validator.ValidateAsync(request, cancellationToken).ConfigureAwait(false);
		if (!validation.IsValid)
			return Outcome<BoolResponse>.Err(ErrorCategory.Validation, (IReadOnlyDictionary<string, string[]>)validation.ToDictionary());

		var user = new NorseUser { UserName = request.Email, Email = request.Email };
		var result = await userManager.CreateAsync(user, request.Password).ConfigureAwait(false);

		if (!result.Succeeded)
		{
			// Only a genuine duplicate is Conflict — Buvy's explicit call, so a legitimate user sees
			// "that email's taken" and doesn't retry a doomed registration 10,000 times (spec §9.3).
			// Everything else (password-policy codes) is Validation — a rejected password isn't a conflict.
			var isDuplicate = result.Errors.Any(e => e.Code is "DuplicateUserName" or "DuplicateEmail");
			var category = isDuplicate ? ErrorCategory.Conflict : ErrorCategory.Validation;
			var errors = result.Errors
				.GroupBy(e => e.Code)
				.ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray());
			return Outcome<BoolResponse>.Err(category, errors);
		}

		return Outcome<BoolResponse>.Ok(new BoolResponse { Value = true });
	}
}
