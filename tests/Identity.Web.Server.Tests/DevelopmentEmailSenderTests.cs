using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

public sealed class DevelopmentEmailSenderTests
{
	const string Email = "u@example.test";

	readonly FakeLogger<DevelopmentEmailSender> _logger = new();
	readonly NorseUser _user = new();

	DevelopmentEmailSender Sender => new(_logger);

	[Fact]
	async Task A_password_reset_link_is_logged_at_information()
	{
		var link = "https://example.test/Account/ResetPassword?code=abc";

		await Sender.SendPasswordResetLinkAsync(_user, Email, link);

		ShouldHaveLoggedOnce(link);
	}

	[Fact]
	async Task A_confirmation_link_is_logged_at_information()
	{
		var link = "https://example.test/Account/ConfirmEmail?userId=u&code=abc";

		await Sender.SendConfirmationLinkAsync(_user, Email, link);

		ShouldHaveLoggedOnce(link);
	}

	[Fact]
	async Task A_password_reset_code_is_logged_at_information()
	{
		var code = "123456";

		await Sender.SendPasswordResetCodeAsync(_user, Email, code);

		ShouldHaveLoggedOnce(code);
	}

	void ShouldHaveLoggedOnce(string value)
	{
		var record = _logger.Collector.GetSnapshot().ShouldHaveSingleItem();
		record.Level.ShouldBe(LogLevel.Information);
		record.Message.ShouldContain(value);
		record.Message.ShouldContain(Email);
	}
}
