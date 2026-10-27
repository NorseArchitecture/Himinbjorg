using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;
using Norse.Primitives.Pii;

namespace Norse.Identity.Web.Server;

/// <summary>
///     Resets a password with the emailed reset code. Anti-enumeration: an unknown or erased address, a malformed
///     code and a rejected code all answer the one static <see cref="ErrorCategory.InvalidCredentials" /> instance,
///     so whether an account exists is never revealed. Every other answer needs a valid token, which the manager
///     verifies before the password validators run.
/// </summary>
/// <param name="userManager">Finds the account and resets its password.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
sealed class ResetPasswordHandler(UserManager<NorseUser> userManager, IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<ResetPasswordCommand, NavigationResult>
{
	static readonly Failed _invalidCode =
		new(Problem.ModelError(ErrorCategory.InvalidCredentials, "The reset link is invalid or has expired."));

	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(ResetPasswordCommand request,
		CancellationToken cancellationToken = default)
	{
		var wire = request.Request;

		// The server-side validator run guarantees a proven stamp before this handler executes — this guard is the
		// tripwire for a hostile caller or a misregistered validator, keyed to the same wire field the client renders.
		if (!wire.Email.TryGetValue(out Success<EmailAddress> email))
			return Outcome<NavigationResult>.Err(ErrorCategory.Validation,
				new Dictionary<string, string[]>
				{
					[nameof(ResetPasswordRequest.Email)] = ["Enter a valid email address (local@domain.tld)."]
				});

		// WireValue is the deliberate plaintext egress — Identity's store speaks canonical strings.
		var found = await userManager.Outcome.FindByEmailAsync(email.Value.WireValue, cancellationToken)
			.ConfigureAwait(false);
		// No such account and an erased one answer exactly what a bad link against a real account does -- the one
		// static instance -- so a junk code cannot probe for existence; anything else passes through.
		if (!found.TryGetValue(out Success<NorseUser> user))
			return found.TryGetValue(out Failed lookupFailed)
				&& lookupFailed.Problem.Category is not (ErrorCategory.NotFound or ErrorCategory.Erased) ?
					new Outcome<NavigationResult>(lookupFailed) :
					new Outcome<NavigationResult>(_invalidCode);

		if (!IdentityTokens.TryDecode(wire.Code, out var token))
			return new Outcome<NavigationResult>(_invalidCode);

		var reset = await userManager.Outcome.ResetPasswordAsync(user.Value, token, wire.Password, cancellationToken)
			.ConfigureAwait(false);
		if (!reset.TryGetValue(out Failed failed))
			return Confirmation();

		return failed.Problem.Category switch
		{
			ErrorCategory.InvalidCredentials => new Outcome<NavigationResult>(_invalidCode),
			ErrorCategory.Validation => Outcome<NavigationResult>.Err(ErrorCategory.Validation,
				IdentityErrorFields.Regroup(failed.Problem.Errors)),
			_ => new Outcome<NavigationResult>(failed)
		};
	}

	Outcome<NavigationResult> Confirmation() =>
		Outcome<NavigationResult>.Ok(new NavigationResult
		{
			NextUrl = UriHelper.BuildRelative(httpContextAccessor.HttpContext!.Request.PathBase,
				"/Account/ResetPasswordConfirmation")
		});
}
