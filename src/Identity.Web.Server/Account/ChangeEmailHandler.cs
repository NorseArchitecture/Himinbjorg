using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;
using Norse.Primitives.Pii;

namespace Norse.Identity.Web.Server.Account;

/// <summary>
///     Starts a change of the caller's email: mints a change token for the new address and sends its confirmation
///     link to that address through <see cref="IEmailSender{TUser}" /> (never a logger — the link is a credential).
///     Nothing is written until the link is confirmed (<see cref="ConfirmEmailChangeHandler" />), so the answer is a
///     plain acknowledgment. The current address, in any case, is refused on the new-email field before any token is
///     minted. The fold's failures pass through unchanged.
/// </summary>
/// <param name="userManager">Loads the caller, reads the current email and mints the change token.</param>
/// <param name="emailSender">Sends the change-confirmation link.</param>
/// <param name="principalAccessor">Reaches the caller's principal.</param>
/// <param name="httpContextAccessor">Reaches the live request the link is built from.</param>
sealed class ChangeEmailHandler(
	UserManager<NorseUser> userManager,
	IEmailSender<NorseUser> emailSender,
	IPrincipalAccessor principalAccessor,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<ChangeEmailCommand, BoolResponse>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<BoolResponse>> Handle(ChangeEmailCommand request,
		CancellationToken cancellationToken = default)
	{
		// The server-side validator run guarantees a proven stamp before this handler executes — this guard is the
		// tripwire for a hostile caller or a misregistered validator, keyed to the same wire field the client renders.
		if (!request.Request.NewEmail.TryGetValue(out Success<EmailAddress> parsed))
			return Outcome<BoolResponse>.Err(ErrorCategory.Validation,
				new Dictionary<string, string[]>
				{
					[nameof(ChangeEmailRequest.NewEmail)] = ["Enter a valid email address (local@domain.tld)."]
				});

		var principal = await principalAccessor.GetPrincipalAsync(cancellationToken).ConfigureAwait(false);
		var found = await userManager.Outcome.GetUserAsync(principal, cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> user);

		// WireValue is the deliberate plaintext egress — Identity's store speaks canonical strings.
		var newEmail = parsed.Value.WireValue;
		var current = await userManager.GetEmailAsync(user.Value).ConfigureAwait(false);
		if (string.Equals(current, newEmail, StringComparison.OrdinalIgnoreCase))
			return Outcome<BoolResponse>.Err(ErrorCategory.Validation,
				new Dictionary<string, string[]> { [nameof(ChangeEmailRequest.NewEmail)] = ["Your email is unchanged."] });

		var token = await userManager.GenerateChangeEmailTokenAsync(user.Value, newEmail).ConfigureAwait(false);
		var code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
		var link = AccountLinks.ConfirmEmailChange(httpContextAccessor.HttpContext!.Request, user.Value.Id.ToString(),
			newEmail, code);
		await emailSender.SendConfirmationLinkAsync(user.Value, newEmail, link).ConfigureAwait(false);
		return Outcome<BoolResponse>.Ok(new BoolResponse { Value = true });
	}
}
