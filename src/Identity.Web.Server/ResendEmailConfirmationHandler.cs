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

namespace Norse.Identity.Web.Server;

/// <summary>
///     Re-sends the email-confirmation link. Always acknowledged: an unknown or erased address, or any other lookup
///     failure, answers exactly what a real send does, so the wire shape cannot enumerate accounts.
/// </summary>
/// <param name="userManager">Finds the account and mints the confirmation token.</param>
/// <param name="emailSender">Sends the confirmation link.</param>
/// <param name="httpContextAccessor">Reaches the live request the link is built from.</param>
sealed class ResendEmailConfirmationHandler(
	UserManager<NorseUser> userManager,
	IEmailSender<NorseUser> emailSender,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<ResendEmailConfirmationCommand, BoolResponse>
{
	static readonly Outcome<BoolResponse> _acknowledged = Outcome<BoolResponse>.Ok(new BoolResponse { Value = true });

	/// <inheritdoc />
	public async ValueTask<Outcome<BoolResponse>> Handle(ResendEmailConfirmationCommand request,
		CancellationToken cancellationToken = default)
	{
		// The server-side validator run guarantees a proven stamp before this handler executes — this guard is the
		// tripwire for a hostile caller or a misregistered validator, keyed to the same wire field the client renders.
		if (!request.Request.Email.TryGetValue(out Success<EmailAddress> email))
			return Outcome<BoolResponse>.Err(ErrorCategory.Validation,
				new Dictionary<string, string[]>
				{
					[nameof(ResendEmailConfirmationRequest.Email)] = ["Enter a valid email address (local@domain.tld)."]
				});

		// WireValue is the deliberate plaintext egress — Identity's store speaks canonical strings.
		var found = await userManager.Outcome.FindByEmailAsync(email.Value.WireValue, cancellationToken)
			.ConfigureAwait(false);
		if (!found.TryGetValue(out Success<NorseUser> user))
			return _acknowledged;

		var token = await userManager.GenerateEmailConfirmationTokenAsync(user.Value).ConfigureAwait(false);
		var code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
		await emailSender.SendConfirmationLinkAsync(user.Value, email.Value.WireValue,
				AccountLinks.ConfirmEmail(httpContextAccessor.HttpContext!.Request, user.Value.Id.ToString(), code))
			.ConfigureAwait(false);
		return _acknowledged;
	}
}
