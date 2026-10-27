using Microsoft.AspNetCore.Identity;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server;

/// <summary>
///     Development only; resolved by <c>AddNorseAuthenticationService</c> under
///     <see cref="Environments.Development" /> and nowhere else; logs credentials by design. Each link or code is
///     written verbatim at <see cref="LogLevel.Information" /> so a developer can follow it without a mail server:
///     a reset link, a reset code and a confirmation link are credentials, which is why no other environment ever
///     resolves this sender.
/// </summary>
/// <param name="logger">Receives one record per message the sender would have delivered.</param>
sealed partial class DevelopmentEmailSender(ILogger<DevelopmentEmailSender> logger) : IEmailSender<NorseUser>
{
	/// <inheritdoc />
	public Task SendConfirmationLinkAsync(NorseUser user, string email, string confirmationLink)
	{
		ConfirmationLink(logger, email, confirmationLink);
		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task SendPasswordResetLinkAsync(NorseUser user, string email, string resetLink)
	{
		PasswordResetLink(logger, email, resetLink);
		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task SendPasswordResetCodeAsync(NorseUser user, string email, string resetCode)
	{
		PasswordResetCode(logger, email, resetCode);
		return Task.CompletedTask;
	}

	[LoggerMessage(Level = LogLevel.Information, Message = "Email confirmation link for {Email}: {Link}")]
	static partial void ConfirmationLink(ILogger logger, string email, string link);

	[LoggerMessage(Level = LogLevel.Information, Message = "Password reset link for {Email}: {Link}")]
	static partial void PasswordResetLink(ILogger logger, string email, string link);

	[LoggerMessage(Level = LogLevel.Information, Message = "Password reset code for {Email}: {Code}")]
	static partial void PasswordResetCode(ILogger logger, string email, string code);
}
