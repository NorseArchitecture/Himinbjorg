using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

public sealed class ResetPasswordHandlerTests
{
	const string Email = "user@example.com";
	const string Token = "reset/token+with=padding";
	const string NewPassword = "correct-horse-battery-1A!";

	static readonly string _code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(Token));

	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly NorseUser _user = new() { UserName = Email, Email = Email };

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task A_valid_reset_answers_the_confirmation_url()
	{
		_userManager.FindByEmailAsync(Email).Returns(_user);
		_userManager.ResetPasswordAsync(_user, Token, NewPassword).Returns(IdentityResult.Success);

		var outcome = await HandleAsync();

		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldBe("/Account/ResetPasswordConfirmation");
	}

	[Fact]
	async Task An_unknown_or_erased_email_answers_the_same_invalid_link_problem_instance()
	{
		_userManager.FindByEmailAsync(Email).Returns((NorseUser?)null);
		var unknown = ProblemOf(await HandleAsync());
		_userManager.FindByEmailAsync(Email)
			.ThrowsAsync(new KeyDestroyedException(new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch)));
		var erased = ProblemOf(await HandleAsync());
		await _userManager.DidNotReceiveWithAnyArgs().ResetPasswordAsync(default!, default!, default!);
		_userManager.FindByEmailAsync(Email).Returns(_user);
		_userManager.ResetPasswordAsync(_user, Token, NewPassword)
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().InvalidToken()));
		var invalidToken = ProblemOf(await HandleAsync());

		unknown.ShouldBeSameAs(invalidToken);
		erased.ShouldBeSameAs(invalidToken);
		invalidToken.Category.ShouldBe(ErrorCategory.InvalidCredentials);
		await _userManager.Received(1).ResetPasswordAsync(Arg.Any<NorseUser>(), Arg.Any<string>(), Arg.Any<string>());
	}

	[Fact]
	async Task An_invalid_token_answers_InvalidCredentials_with_the_local_message()
	{
		_userManager.FindByEmailAsync(Email).Returns(_user);
		_userManager.ResetPasswordAsync(_user, Token, NewPassword)
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().InvalidToken()));

		var problem = ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.InvalidCredentials);
		problem.Errors.Keys.ShouldBe([string.Empty]);
		problem.Errors[string.Empty].ShouldBe(["The reset link is invalid or has expired."]);
	}

	[Fact]
	async Task A_malformed_code_answers_the_same_InvalidCredentials()
	{
		_userManager.FindByEmailAsync(Email).Returns(_user);
		_userManager.ResetPasswordAsync(_user, Token, NewPassword)
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().InvalidToken()));
		var invalidToken = ProblemOf(await HandleAsync());

		var malformed = ProblemOf(await HandleAsync("not*base64"));

		malformed.ShouldBeSameAs(invalidToken);
		await _userManager.Received(1).ResetPasswordAsync(Arg.Any<NorseUser>(), Arg.Any<string>(), Arg.Any<string>());
	}

	[Fact]
	async Task Password_rule_failures_regroup_onto_the_Password_field()
	{
		IdentityErrorDescriber describer = new();
		_userManager.FindByEmailAsync(Email).Returns(_user);
		_userManager.ResetPasswordAsync(_user, Token, NewPassword)
			.Returns(IdentityResult.Failed(describer.PasswordTooShort(12), describer.PasswordRequiresDigit()));

		var problem = ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors.Keys.ShouldBe([nameof(ResetPasswordRequest.Password)]);
		problem.Errors[nameof(ResetPasswordRequest.Password)]
			.ShouldBe([describer.PasswordTooShort(12).Description, describer.PasswordRequiresDigit().Description]);
	}

	[Fact]
	async Task An_indeterminate_write_passes_through()
	{
		_userManager.FindByEmailAsync(Email).Returns(_user);
		_userManager.ResetPasswordAsync(_user, Token, NewPassword)
			.ThrowsAsync(new IndeterminateWriteException("the reset", new TimeoutException()));

		ProblemOf(await HandleAsync()).Category.ShouldBe(ErrorCategory.Indeterminate);
	}

	ValueTask<Outcome<NavigationResult>> HandleAsync(string? code = null)
	{
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(new DefaultHttpContext());
		ResetPasswordHandler handler = new(_userManager, accessor);
		return handler.Handle(new(new ResetPasswordRequest
		{
			EmailInput = Email,
			Code = code ?? _code,
			Password = NewPassword
		}), Cancellation);
	}

	static Problem ProblemOf(Outcome<NavigationResult> outcome)
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem;
	}
}
