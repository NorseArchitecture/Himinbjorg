using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

public sealed class ResendEmailConfirmationHandlerTests
{
	const string Email = "user@example.com";
	const string ConfirmationToken = "confirm/token+with=padding";

	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly IEmailSender<NorseUser> _emailSender = Substitute.For<IEmailSender<NorseUser>>();
	readonly NorseUser _user = new() { UserName = Email, Email = Email };

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task An_unknown_email_answers_true_and_sends_nothing()
	{
		_userManager.FindByEmailAsync(Email).Returns((NorseUser?)null);

		ValueOf(await HandleAsync()).ShouldBeTrue();
		_emailSender.ReceivedCalls().ShouldBeEmpty();
	}

	[Fact]
	async Task A_known_email_sends_an_absolute_confirmation_link_and_answers_true()
	{
		_userManager.FindByEmailAsync(Email).Returns(_user);
		_userManager.GenerateEmailConfirmationTokenAsync(_user).Returns(ConfirmationToken);
		string? link = null;
		await _emailSender.SendConfirmationLinkAsync(_user, Email, Arg.Do<string>(sent => link = sent));

		ValueOf(await HandleAsync()).ShouldBeTrue();

		await _emailSender.Received(1).SendConfirmationLinkAsync(_user, Email, Arg.Any<string>());
		var prefix = $"https://example.test/base/Account/ConfirmEmail?userId={_user.Id}&code=";
		link.ShouldNotBeNull().ShouldStartWith(prefix);
		var code = Uri.UnescapeDataString(link[prefix.Length..]);
		Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code)).ShouldBe(ConfirmationToken);
	}

	ValueTask<Outcome<BoolResponse>> HandleAsync()
	{
		DefaultHttpContext context = new();
		context.Request.Scheme = "https";
		context.Request.Host = new("example.test");
		context.Request.PathBase = "/base";
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(context);
		ResendEmailConfirmationHandler handler = new(_userManager, _emailSender, accessor);
		return handler.Handle(new(new ResendEmailConfirmationRequest { EmailInput = Email }), Cancellation);
	}

	static bool ValueOf(Outcome<BoolResponse> outcome)
	{
		outcome.TryGetValue(out Success<BoolResponse> success).ShouldBeTrue();
		return success.Value.Value;
	}
}
