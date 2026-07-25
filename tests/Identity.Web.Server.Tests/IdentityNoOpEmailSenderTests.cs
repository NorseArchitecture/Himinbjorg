using Microsoft.AspNetCore.Identity;

namespace Norse.Identity.Web.Server.Tests;

public sealed class IdentityNoOpEmailSenderTests
{
	readonly IEmailSender<NorseUser> _sender = new IdentityNoOpEmailSender();
	readonly NorseUser _user = new();

	[Fact]
	async Task SendConfirmationLinkAsync_completes_without_throwing() =>
		await _sender.SendConfirmationLinkAsync(_user, "user@example.com", "https://example.com/confirm");

	[Fact]
	async Task SendPasswordResetLinkAsync_completes_without_throwing() =>
		await _sender.SendPasswordResetLinkAsync(_user, "user@example.com", "https://example.com/reset");

	[Fact]
	async Task SendPasswordResetCodeAsync_completes_without_throwing() =>
		await _sender.SendPasswordResetCodeAsync(_user, "user@example.com", "123456");
}
