using Microsoft.AspNetCore.Http;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

public sealed class LoginHandlerTests
{
	// Rejection-of-an-invalid-request coverage moved to Midgard's ValidationBehavior tests —
	// ValidationBehavior owns validation now, LoginHandler never sees an invalid request.

	static LoginHandler CreateHandler(
		Microsoft.AspNetCore.Identity.SignInManager<NorseUser> signInManager,
		IDeferredSignIn? deferredSignIn = null,
		HttpContext? httpContext = null)
	{
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(httpContext ?? new DefaultHttpContext());
		return new LoginHandler(signInManager, deferredSignIn ?? Substitute.For<IDeferredSignIn>(), accessor);
	}

	[Fact]
	async Task Returns_LockedOut_when_the_store_reports_lockout()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "wrong-password", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.LockedOut);
		var handler = CreateHandler(signInManager);
		LoginCommand command = new(new LoginRequest { Email = "user@example.com", Password = "wrong-password" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

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
		var handler = CreateHandler(signInManager);
		LoginCommand command = new(new LoginRequest { Email = "user@example.com", Password = "wrong-password" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

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
		var handler = CreateHandler(signInManager);
		LoginCommand command = new(new LoginRequest { Email = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LoginResult> success).ShouldBeTrue();
		success.Value.Succeeded.ShouldBeTrue();
	}

	[Fact]
	async Task Returns_Succeeded_false_never_an_error_when_credentials_are_wrong()
	{
		// The whole point of §9.3's anti-enumeration collapse: wrong username and wrong password both
		// land here, as a successful check that returned false — never Outcome.Err(InvalidCredentials).
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "wrong-password", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Failed);
		var handler = CreateHandler(signInManager);
		LoginCommand command = new(new LoginRequest { Email = "user@example.com", Password = "wrong-password" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LoginResult> success).ShouldBeTrue();
		success.Value.Succeeded.ShouldBeFalse();
	}

	[Fact]
	async Task DeferredCompletionUrl_is_null_when_nothing_is_stashed_on_HttpContext()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Success);
		var handler = CreateHandler(signInManager);
		LoginCommand command = new(new LoginRequest { Email = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LoginResult> success).ShouldBeTrue();
		success.Value.DeferredCompletionUrl.ShouldBeNull();
	}

	[Fact]
	async Task DeferredCompletionUrl_is_populated_when_stashed_on_HttpContext()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Success);
		var deferredSignIn = Substitute.For<IDeferredSignIn>();
		deferredSignIn.BuildCompletionUrl(Arg.Any<string>(), Arg.Any<string>())
			.Returns(call => $"/_auth/complete?key={call.ArgAt<string>(0)}&returnUrl={Uri.EscapeDataString(call.ArgAt<string>(1))}");
		DefaultHttpContext httpContext = new();
		httpContext.Items[NorseSignInManager.DeferredSignInKeyItemName] = "stashed-key";
		var handler = CreateHandler(signInManager, deferredSignIn, httpContext);
		LoginCommand command = new(new LoginRequest { Email = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LoginResult> success).ShouldBeTrue();
		success.Value.DeferredCompletionUrl.ShouldNotBeNull();
		success.Value.DeferredCompletionUrl.ShouldContain("stashed-key");
	}
}
