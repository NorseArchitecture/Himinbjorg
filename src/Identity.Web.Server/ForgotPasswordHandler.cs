using System.Text;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;
using Norse.Primitives.Pii;

namespace Norse.Identity.Web.Server;

/// <summary>
///     Emails a password-reset link to a confirmed account. Anti-enumeration: an unknown, erased or unconfirmed address
///     answers exactly what a real one does, the confirmation page, through the one <see cref="Confirmation" /> path,
///     so the wire shape cannot differ.
/// </summary>
/// <param name="userManager">Finds the account and mints the reset token.</param>
/// <param name="emailSender">Sends the reset link.</param>
/// <param name="httpContextAccessor">Reaches the live request the link and the confirmation URL are built from.</param>
sealed class ForgotPasswordHandler(
	UserManager<NorseUser> userManager,
	IEmailSender<NorseUser> emailSender,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<ForgotPasswordCommand, NavigationResult>
{
	HttpRequest Request =>
		httpContextAccessor.HttpContext!.Request;

	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(ForgotPasswordCommand request,
		CancellationToken cancellationToken = default)
	{
		// The server-side validator run guarantees a proven stamp before this handler executes — this guard is the
		// tripwire for a hostile caller or a misregistered validator, keyed to the same wire field the client renders.
		if (!request.Request.Email.TryGetValue(out Success<EmailAddress> email))
			return Outcome<NavigationResult>.Err(ErrorCategory.Validation,
				new Dictionary<string, string[]>
				{
					[nameof(ForgotPasswordRequest.Email)] = ["Enter a valid email address (local@domain.tld)."]
				});

		// WireValue is the deliberate plaintext egress — Identity's store speaks canonical strings. Not found, erased
		// and any other failure all answer the confirmation page, as does an address nobody has confirmed.
		var found = await userManager.Outcome.FindByEmailAsync(email.Value.WireValue, cancellationToken)
			.ConfigureAwait(false);
		if (!found.TryGetValue(out Success<NorseUser> user)
			|| !await userManager.IsEmailConfirmedAsync(user.Value).ConfigureAwait(false))
			return Confirmation();

		var token = await userManager.GeneratePasswordResetTokenAsync(user.Value).ConfigureAwait(false);
		var code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
		await emailSender.SendPasswordResetLinkAsync(user.Value, email.Value.WireValue,
				AccountLinks.ResetPassword(Request, code))
			.ConfigureAwait(false);
		return Confirmation();
	}

	Outcome<NavigationResult> Confirmation() =>
		Outcome<NavigationResult>.Ok(new NavigationResult
		{
			NextUrl = UriHelper.BuildRelative(Request.PathBase, "/Account/ForgotPasswordConfirmation")
		});
}
