using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;
using Norse.Primitives.Pii;

namespace Norse.Identity.Web.Server;

sealed class RegisterHandler(UserManager<NorseUser> userManager)
	: IRequestHandler<RegisterCommand, NavigationResult>
{
	public async ValueTask<Outcome<NavigationResult>> Handle(RegisterCommand request,
		CancellationToken cancellationToken = default)
	{
		var wire = request.Request;

		// The server-side validator run guarantees a proven stamp before this handler executes —
		// this guard is the tripwire for a hostile caller or a misregistered validator, keyed to the
		// same wire field the client renders.
		if (!wire.Email.TryGetValue(out Success<EmailAddress> email))
			return Outcome<NavigationResult>.Err(ErrorCategory.Validation,
				new Dictionary<string, string[]>
				{
					[nameof(RegisterRequest.Email)] = ["Enter a valid email address (local@domain.tld)."]
				});

		// WireValue is the deliberate plaintext egress — Identity's store speaks canonical strings.
		NorseUser user = new() { UserName = email.Value.WireValue, Email = email.Value.WireValue };
		var outcome = await userManager.Outcome.CreateAsync(user, wire.Password, cancellationToken).ConfigureAwait(false);

		// The next hop is server-resolved (the login page today; the email-confirmation page the day
		// that flow lands) — the client navigates it unconditionally, with no route of its own.
		// The category is the mapping table's (explicit-writes spec §4.12), never decided here: a genuine
		// duplicate is Conflict (Buvy's explicit call, so a legitimate user sees "that email's taken" and
		// doesn't retry a doomed registration 10,000 times, spec §9.3), a rejected password Validation, and
		// anything unclassified a Fault.
		if (!outcome.TryGetValue(out Failed failed))
			return Outcome<NavigationResult>.Ok(new NavigationResult { NextUrl = "/Account/Login" });
		// The view keys errors by IdentityError.Code; regrouped here by the WIRE FIELD each belongs on — the
		// client's ServerErrorCoordinator builds a FieldIdentifier from this dictionary's keys, and a
		// key like "PasswordRequiresNonAlphanumeric" matches no bound field, so the message renders
		// nowhere (neither inline, since no field has that name, nor in the model-level summary, since
		// that only fires when Errors is empty) -- silently dropped, reproduced live 2026-08-07.
		var errors = failed.Problem.Errors
			.GroupBy(static error => FieldFor(error.Key))
			.ToDictionary(static group => group.Key, string[] (group) => [.. group.SelectMany(static error => error.Value)]);
		return Outcome<NavigationResult>.Err(failed.Problem.Category, errors);
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
			"PasswordRequiresDigit" or "PasswordRequiresLower"
			or "PasswordRequiresUpper" => nameof(RegisterRequest.Password),
		_ => ""
	};
}
