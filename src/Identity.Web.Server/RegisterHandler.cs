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
		// Grouped by the WIRE FIELD the error belongs on, never by IdentityError.Code directly — the
		// client's ServerErrorCoordinator builds a FieldIdentifier from this dictionary's keys, and a
		// key like "PasswordRequiresNonAlphanumeric" matches no bound field, so the message renders
		// nowhere (neither inline, since no field has that name, nor in the model-level summary, since
		// that only fires when Errors is empty) -- silently dropped, reproduced live 2026-08-07.
		var errors = result.Errors
			.GroupBy(e => FieldFor(e.Code))
			.ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray());
		return Outcome<RegisterResult>.Err(category, errors);
	}

	// UserName is always set to Email in this handler, so every user-name-shaped code belongs on the
	// Email field too. Every code this describer actually emits from a role-free CreateAsync call is
	// named here explicitly rather than pattern-matched, so a future IdentityErrorDescriber code this
	// platform has never seen fails safe to the model-level summary (empty key) instead of silently
	// mapping to the wrong field.
	static string FieldFor(string identityErrorCode) => identityErrorCode switch
	{
		"DuplicateUserName" or "DuplicateEmail" or "InvalidUserName" or "InvalidEmail" => nameof(RegisterRequest.Email),
		"PasswordTooShort" or "PasswordRequiresUniqueChars" or "PasswordRequiresNonAlphanumeric" or
			"PasswordRequiresDigit" or "PasswordRequiresLower" or "PasswordRequiresUpper" => nameof(RegisterRequest.Password),
		_ => "",
	};
}
