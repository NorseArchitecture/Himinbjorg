using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

public sealed class ConfirmEmailHandlerTests
{
	const string Token = "confirm/token+with=padding";

	static readonly string _code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(Token));

	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly NorseUser _user = new() { UserName = "user@example.com", Email = "user@example.com" };

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	string UserId =>
		_user.Id.ToString();

	[Fact]
	async Task Success_answers_true()
	{
		_userManager.FindByIdAsync(UserId).Returns(_user);
		_userManager.ConfirmEmailAsync(_user, Token).Returns(IdentityResult.Success);

		var outcome = await HandleAsync();

		outcome.TryGetValue(out Success<BoolResponse> success).ShouldBeTrue();
		success.Value.Value.ShouldBeTrue();
		await _userManager.Received(1).ConfirmEmailAsync(_user, Token);
	}

	[Fact]
	async Task An_unknown_user_answers_NotFound()
	{
		_userManager.FindByIdAsync(UserId).Returns((NorseUser?)null);

		ProblemOf(await HandleAsync()).Category.ShouldBe(ErrorCategory.NotFound);
		await _userManager.DidNotReceiveWithAnyArgs().ConfirmEmailAsync(default!, default!);
	}

	[Fact]
	async Task An_invalid_token_answers_InvalidCredentials()
	{
		_userManager.FindByIdAsync(UserId).Returns(_user);
		_userManager.ConfirmEmailAsync(_user, Token)
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().InvalidToken()));

		ProblemOf(await HandleAsync()).Category.ShouldBe(ErrorCategory.InvalidCredentials);
	}

	[Fact]
	async Task A_malformed_code_answers_InvalidCredentials()
	{
		_userManager.FindByIdAsync(UserId).Returns(_user);

		ProblemOf(await HandleAsync("not*base64")).Category.ShouldBe(ErrorCategory.InvalidCredentials);
		await _userManager.DidNotReceiveWithAnyArgs().ConfirmEmailAsync(default!, default!);
	}

	[Fact]
	async Task An_erased_subject_answers_Erased()
	{
		_userManager.FindByIdAsync(UserId)
			.ThrowsAsync(new KeyDestroyedException(new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch)));

		ProblemOf(await HandleAsync()).Category.ShouldBe(ErrorCategory.Erased);
	}

	ValueTask<Outcome<BoolResponse>> HandleAsync(string? code = null)
	{
		ConfirmEmailHandler handler = new(_userManager);
		return handler.Handle(new(new ConfirmEmailRequest { UserId = UserId, Code = code ?? _code }), Cancellation);
	}

	static Problem ProblemOf(Outcome<BoolResponse> outcome)
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem;
	}
}
