using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

public sealed class LoginHandlerTests
{
	// Rejection-of-an-invalid-request coverage moved to Midgard's ValidationBehavior tests —
	// ValidationBehavior owns validation now, LoginHandler never sees an invalid request.

	[Fact]
	async Task Returns_LockedOut_when_the_store_reports_lockout()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "wrong-password", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.LockedOut);
		LoginHandler handler = new(signInManager);
		LoginRequest request = new() { Email = "user@example.com", Password = "wrong-password" };

		var outcome = await handler.Handle(request, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.LockedOut);
		failed.Problem.Errors[""].ShouldNotBeEmpty();
	}

	[Fact]
	async Task Returns_NotAllowed_with_a_message_when_the_store_reports_not_allowed()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "wrong-password", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.NotAllowed);
		LoginHandler handler = new(signInManager);
		LoginRequest request = new() { Email = "user@example.com", Password = "wrong-password" };

		var outcome = await handler.Handle(request, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.NotAllowed);
		failed.Problem.Errors[""].ShouldNotBeEmpty();
	}

	[Fact]
	async Task Returns_Succeeded_true_when_the_store_signs_in()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Success);
		LoginHandler handler = new(signInManager);
		LoginRequest request = new() { Email = "user@example.com", Password = "correct-horse" };

		var outcome = await handler.Handle(request, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<BoolResponse> success).ShouldBeTrue();
		success.Value.Value.ShouldBeTrue();
	}

	[Fact]
	async Task Returns_Succeeded_false_never_an_error_when_credentials_are_wrong()
	{
		// The whole point of §9.3's anti-enumeration collapse: wrong username and wrong password both
		// land here, as a successful check that returned false — never Outcome.Err(InvalidCredentials).
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "wrong-password", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Failed);
		LoginHandler handler = new(signInManager);
		LoginRequest request = new() { Email = "user@example.com", Password = "wrong-password" };

		var outcome = await handler.Handle(request, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<BoolResponse> success).ShouldBeTrue();
		success.Value.Value.ShouldBeFalse();
	}
}
