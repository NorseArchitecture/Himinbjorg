using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server;

/// <summary>
///     The <see cref="IEmailSender{TUser}" /> every environment but <c>Development</c> resolves: it sends nothing
///     and logs nothing, so no link or code it is handed ever leaves the process. <see cref="DevelopmentEmailSender" />
///     is the development-only logger; a host wiring a real sender registers its own after
///     <c>AddNorseAuthenticationService</c> and wins the resolution.
/// </summary>
public sealed class IdentityNoOpEmailSender : IEmailSender<NorseUser>
{
#pragma warning disable CA1859
	readonly IEmailSender _emailSender = new NoOpEmailSender();
#pragma warning restore CA1859

	/// <inheritdoc />
	public Task SendConfirmationLinkAsync(NorseUser user, string email, string confirmationLink) =>
		_emailSender.SendEmailAsync(email, "Confirm your email",
			$"Please confirm your account by <a href='{confirmationLink}'>clicking here</a>.");

	/// <inheritdoc />
	public Task SendPasswordResetLinkAsync(NorseUser user, string email, string resetLink) =>
		_emailSender.SendEmailAsync(email, "Reset your password",
			$"Please reset your password by <a href='{resetLink}'>clicking here</a>.");

	/// <inheritdoc />
	public Task SendPasswordResetCodeAsync(NorseUser user, string email, string resetCode) =>
		_emailSender.SendEmailAsync(email, "Reset your password",
			$"Please reset your password using the following code: {resetCode}");
}
