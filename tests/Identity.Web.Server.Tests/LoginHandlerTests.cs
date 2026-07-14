using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components;
using NSubstitute;

namespace Norse.Identity.Web.Server.Tests;

public sealed class LoginHandlerTests
{
	[Fact]
	async Task Rejects_an_invalid_request_without_attempting_sign_in()
	{
		var signInManager = MockSignInManager.Create();
		var handler = new LoginHandler(signInManager, new LoginRequestValidator());
		var request = new LoginRequest { Email = "", Password = "" };

		var outcome = await handler.Handle(request, CancellationToken.None);

		outcome.IsSuccess.ShouldBeFalse();
		outcome.Problem!.Category.ShouldBe(ErrorCategory.Validation);
		await signInManager.DidNotReceive().PasswordSignInAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<bool>(), Arg.Any<bool>());
	}

	[Fact]
	async Task Returns_LockedOut_when_the_store_reports_lockout()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "wrong", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.LockedOut);
		var handler = new LoginHandler(signInManager, new LoginRequestValidator());
		var request = new LoginRequest { Email = "user@example.com", Password = "wrong" };

		var outcome = await handler.Handle(request, CancellationToken.None);

		outcome.IsSuccess.ShouldBeFalse();
		outcome.Problem!.Category.ShouldBe(ErrorCategory.LockedOut);
		outcome.Problem!.Errors[""].ShouldNotBeEmpty();
	}

	[Fact]
	async Task Returns_NotAllowed_with_a_message_when_the_store_reports_not_allowed()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "wrong", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.NotAllowed);
		var handler = new LoginHandler(signInManager, new LoginRequestValidator());
		var request = new LoginRequest { Email = "user@example.com", Password = "wrong" };

		var outcome = await handler.Handle(request, CancellationToken.None);

		outcome.IsSuccess.ShouldBeFalse();
		outcome.Problem!.Category.ShouldBe(ErrorCategory.NotAllowed);
		outcome.Problem!.Errors[""].ShouldNotBeEmpty();
	}

	[Fact]
	async Task Returns_Succeeded_true_when_the_store_signs_in()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Success);
		var handler = new LoginHandler(signInManager, new LoginRequestValidator());
		var request = new LoginRequest { Email = "user@example.com", Password = "correct-horse" };

		var outcome = await handler.Handle(request, CancellationToken.None);

		outcome.IsSuccess.ShouldBeTrue();
		outcome.Value!.Value.ShouldBeTrue();
	}

	[Fact]
	async Task Returns_Succeeded_false_never_an_error_when_credentials_are_wrong()
	{
		// The whole point of §9.3's anti-enumeration collapse: wrong username and wrong password both
		// land here, as a successful check that returned false — never Outcome.Err(InvalidCredentials).
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "wrong", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Failed);
		var handler = new LoginHandler(signInManager, new LoginRequestValidator());
		var request = new LoginRequest { Email = "user@example.com", Password = "wrong" };

		var outcome = await handler.Handle(request, CancellationToken.None);

		outcome.IsSuccess.ShouldBeTrue();
		outcome.Value!.Value.ShouldBeFalse();
	}
}
