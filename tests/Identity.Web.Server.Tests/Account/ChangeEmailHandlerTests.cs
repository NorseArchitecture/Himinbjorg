using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests.Account;

public sealed class ChangeEmailHandlerTests
{
	const string NewEmail = "new@example.com";
	const string ChangeToken = "change/token+with=padding";

	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly IEmailSender<NorseUser> _emailSender = Substitute.For<IEmailSender<NorseUser>>();
	readonly NorseUser _user = new() { UserName = "user@example.com", Email = "user@example.com" };

	public ChangeEmailHandlerTests()
	{
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user);
		_userManager.GetEmailAsync(_user).Returns("user@example.com");
		_userManager.GenerateChangeEmailTokenAsync(_user, NewEmail).Returns(ChangeToken);
	}

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task A_new_address_generates_a_token_and_sends_an_absolute_link_and_answers_true()
	{
		string? link = null;
		await _emailSender.SendConfirmationLinkAsync(_user, NewEmail, Arg.Do<string>(sent => link = sent));

		ValueOf(await HandleAsync(NewEmail)).ShouldBeTrue();

		await _emailSender.Received(1).SendConfirmationLinkAsync(_user, "new@example.com",
			Arg.Is<string>(l => l.StartsWith("https://example.test/base/Account/ConfirmEmailChange?")));
		var prefix = $"https://example.test/base/Account/ConfirmEmailChange?userId={_user.Id}&email=new@example.com&code=";
		link.ShouldNotBeNull().ShouldStartWith(prefix);
		var code = Uri.UnescapeDataString(link[prefix.Length..]);
		Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code)).ShouldBe(ChangeToken);
	}

	[Fact]
	async Task The_current_address_in_any_case_answers_Validation_and_sends_nothing()
	{
		_userManager.GetEmailAsync(_user).Returns("User@Example.com");

		var problem = ProblemOf(await HandleAsync("user@example.com"));

		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors.Keys.ShouldBe([nameof(ChangeEmailRequest.NewEmail)]);
		problem.Errors[nameof(ChangeEmailRequest.NewEmail)].ShouldBe(["Your email is unchanged."]);
		await _userManager.DidNotReceiveWithAnyArgs().GenerateChangeEmailTokenAsync(default!, default!);
		_emailSender.ReceivedCalls().ShouldBeEmpty();
	}

	[Fact]
	async Task A_malformed_address_trips_the_wire_with_Validation_on_the_new_email_field()
	{
		var problem = ProblemOf(await HandleAsync("not an email"));

		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors.Keys.ShouldBe([nameof(ChangeEmailRequest.NewEmail)]);
		problem.Errors[nameof(ChangeEmailRequest.NewEmail)].ShouldBe(["Enter a valid email address (local@domain.tld)."]);
		await _userManager.DidNotReceiveWithAnyArgs().GetUserAsync(default!);
		_emailSender.ReceivedCalls().ShouldBeEmpty();
	}

	[Fact]
	async Task An_erased_subject_answers_Erased()
	{
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).ThrowsAsync(new KeyDestroyedException(receipt));

		var problem = ProblemOf(await HandleAsync(NewEmail));

		problem.Category.ShouldBe(ErrorCategory.Erased);
		problem.Receipt.ShouldBeSameAs(receipt);
		await _userManager.DidNotReceiveWithAnyArgs().GenerateChangeEmailTokenAsync(default!, default!);
		_emailSender.ReceivedCalls().ShouldBeEmpty();
	}

	ValueTask<Outcome<BoolResponse>> HandleAsync(string newEmail)
	{
		DefaultHttpContext context = new();
		context.Request.Scheme = "https";
		context.Request.Host = new("example.test");
		context.Request.PathBase = "/base";
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(context);
		ChangeEmailHandler handler = new(_userManager, _emailSender, FakePrincipal.For(_user.Id), accessor);
		return handler.Handle(new(new() { NewEmailInput = newEmail }), Cancellation);
	}

	static bool ValueOf(Outcome<BoolResponse> outcome)
	{
		outcome.TryGetValue(out Success<BoolResponse> success).ShouldBeTrue();
		return success.Value.Value;
	}

	static Problem ProblemOf(Outcome<BoolResponse> outcome)
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem;
	}
}
