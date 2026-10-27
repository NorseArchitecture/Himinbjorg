using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

public sealed class ForgotPasswordHandlerTests
{
	const string Email = "user@example.com";
	const string ConfirmationUrl = "/Account/ForgotPasswordConfirmation";
	const string ResetToken = "reset/token+with=padding";

	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly IEmailSender<NorseUser> _emailSender = Substitute.For<IEmailSender<NorseUser>>();
	readonly NorseUser _user = new() { UserName = Email, Email = Email };

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task An_unknown_email_answers_the_confirmation_url_and_sends_nothing()
	{
		_userManager.FindByEmailAsync(Email).Returns((NorseUser?)null);

		var outcome = await HandleAsync();

		NavigationOf(outcome).NextUrl.ShouldBe(ConfirmationUrl);
		ShouldHaveSentNothing();
	}

	[Fact]
	async Task An_erased_subject_answers_the_confirmation_url_and_sends_nothing()
	{
		_userManager.FindByEmailAsync(Email)
			.ThrowsAsync(new KeyDestroyedException(new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch)));

		var outcome = await HandleAsync();

		NavigationOf(outcome).NextUrl.ShouldBe(ConfirmationUrl);
		ShouldHaveSentNothing();
	}

	[Fact]
	async Task An_unconfirmed_email_answers_the_confirmation_url_and_sends_nothing()
	{
		_userManager.FindByEmailAsync(Email).Returns(_user);
		_userManager.IsEmailConfirmedAsync(_user).Returns(false);

		var outcome = await HandleAsync();

		NavigationOf(outcome).NextUrl.ShouldBe(ConfirmationUrl);
		ShouldHaveSentNothing();
	}

	[Fact]
	async Task A_confirmed_email_sends_an_absolute_reset_link_with_the_encoded_token_and_answers_the_same_url()
	{
		ConfirmedUser();
		string? link = null;
		await _emailSender.SendPasswordResetLinkAsync(_user, Email, Arg.Do<string>(sent => link = sent));

		var outcome = await HandleAsync();

		NavigationOf(outcome).NextUrl.ShouldBe(ConfirmationUrl);
		await _emailSender.Received(1).SendPasswordResetLinkAsync(_user, Email, Arg.Any<string>());
		const string Prefix = "https://example.test/Account/ResetPassword?code=";
		link.ShouldNotBeNull().ShouldStartWith(Prefix);
		var code = Uri.UnescapeDataString(link[Prefix.Length..]);
		Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code)).ShouldBe(ResetToken);
	}

	[Fact]
	async Task Every_branch_answers_the_identical_NavigationResult()
	{
		_userManager.FindByEmailAsync(Email).Returns((NorseUser?)null);
		var unknown = NavigationOf(await HandleAsync());
		_userManager.FindByEmailAsync(Email)
			.ThrowsAsync(new KeyDestroyedException(new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch)));
		var erased = NavigationOf(await HandleAsync());
		_userManager.FindByEmailAsync(Email).Returns(_user);
		_userManager.IsEmailConfirmedAsync(_user).Returns(false);
		var unconfirmed = NavigationOf(await HandleAsync());
		ConfirmedUser();
		var sent = NavigationOf(await HandleAsync());

		erased.ShouldBe(unknown);
		unconfirmed.ShouldBe(unknown);
		sent.ShouldBe(unknown);
	}

	void ConfirmedUser()
	{
		_userManager.FindByEmailAsync(Email).Returns(_user);
		_userManager.IsEmailConfirmedAsync(_user).Returns(true);
		_userManager.GeneratePasswordResetTokenAsync(_user).Returns(ResetToken);
	}

	void ShouldHaveSentNothing() =>
		_emailSender.ReceivedCalls().ShouldBeEmpty();

	ValueTask<Outcome<NavigationResult>> HandleAsync()
	{
		DefaultHttpContext context = new();
		context.Request.Scheme = "https";
		context.Request.Host = new("example.test");
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(context);
		ForgotPasswordHandler handler = new(_userManager, _emailSender, accessor);
		return handler.Handle(new(new ForgotPasswordRequest { EmailInput = Email }), Cancellation);
	}

	static NavigationResult NavigationOf(Outcome<NavigationResult> outcome)
	{
		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		return success.Value;
	}
}
