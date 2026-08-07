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

	// PasswordSignInAsync already collapses "wrong password against a real user" into
	// SignInResult.Failed -- Arg.Any so this fixture answers Failed regardless of which
	// email/password each call site happens to pass.
	static LoginHandler NewHandlerWithFailingSignIn()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<bool>(), Arg.Any<bool>())
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Failed);
		return CreateHandler(signInManager);
	}

	// A second, semantically distinct construction path for the same SignInResult.Failed outcome --
	// PasswordSignInAsync collapses "no such user" into the identical case as "wrong password", so
	// this fixture proves the anti-enumeration test below isn't just reusing one handler instance for
	// both scenarios.
	static LoginHandler NewHandlerWithUnknownUser()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<bool>(), Arg.Any<bool>())
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Failed);
		return CreateHandler(signInManager);
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
	async Task Returns_a_success_outcome_when_the_store_signs_in()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Success);
		var handler = CreateHandler(signInManager);
		LoginCommand command = new(new LoginRequest { Email = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LoginResult> _).ShouldBeTrue();
	}

	[Fact]
	async Task Wrong_credentials_produce_an_invalid_credentials_model_error()
	{
		var handler = NewHandlerWithFailingSignIn();
		LoginCommand command = new(new LoginRequest { Email = "who@example.com", Password = "nope" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.InvalidCredentials);
		failed.Problem.Errors[string.Empty].ShouldBe(["Invalid email or password."]);
	}

	[Fact]
	async Task Wrong_user_and_wrong_password_produce_the_same_problem_instance()
	{
		// Record equality would lie here: Problem.Errors is a dictionary, which records compare by
		// reference — two separately built identical Problems are UNEQUAL. The implementation
		// therefore holds ONE static instance and every credential-failure path returns it, making
		// anti-enumeration a reference-identity guarantee rather than a structural coincidence.
		var unknownUserOutcome = await NewHandlerWithUnknownUser().Handle(
			new(new LoginRequest { Email = "ghost@example.com", Password = "x" }), TestContext.Current.CancellationToken);
		var wrongPasswordOutcome = await NewHandlerWithFailingSignIn().Handle(
			new(new LoginRequest { Email = "real@example.com", Password = "x" }), TestContext.Current.CancellationToken);

		unknownUserOutcome.TryGetValue(out Failed first).ShouldBeTrue();
		wrongPasswordOutcome.TryGetValue(out Failed second).ShouldBeTrue();
		first.Problem.ShouldBeSameAs(second.Problem);

		// Structural belt over the identity suspenders: the one instance carries exactly the collapse.
		first.Problem.Category.ShouldBe(ErrorCategory.InvalidCredentials);
		first.Problem.Errors.Keys.ShouldBe([string.Empty]);
		first.Problem.Errors[string.Empty].ShouldBe(["Invalid email or password."]);
		first.Problem.CorrelationId.ShouldBeNull();
	}

	[Fact]
	async Task Returns_the_two_factor_challenge_url_on_the_success_side_when_the_password_is_correct_but_2fa_is_pending()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.TwoFactorRequired);
		var handler = CreateHandler(signInManager);
		LoginCommand command = new(new LoginRequest { Email = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		// The correct password must never route into the same branch a wrong password does -- that
		// would make a 2FA-enabled user's genuinely correct password indistinguishable from a failed
		// one, defeating the entire point of a second factor. The server resolves NextUrl to the full
		// navigation target itself -- the client gets a concrete URL, never a flag to branch on or a
		// route to build.
		outcome.TryGetValue(out Success<LoginResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldBe("/Account/LoginWith2fa?RememberMe=false");
	}

	[Fact]
	async Task The_two_factor_challenge_url_carries_the_caller_s_RememberMe_choice()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", true, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.TwoFactorRequired);
		var handler = CreateHandler(signInManager);
		LoginCommand command = new(new LoginRequest { Email = "user@example.com", Password = "correct-horse", RememberMe = true });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LoginResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldBe("/Account/LoginWith2fa?RememberMe=true");
	}

	// The exact scenario the leading-slash bug lived in: 2FA required AND the cookie had to be
	// deferred (an established circuit). This drives through the real TryGetDeferredCompletionUrl
	// detour instead of the `?? challengeUrl` fallback the two tests above exercise -- asserting the
	// resulting URL's returnUrl segment is root-relative, since Midgard's completion endpoint emits it
	// into a meta-refresh with no <base> tag: a path-relative value there 404s (RFC 3986 relative
	// resolution against /_auth/complete strips the last path segment), a root-relative one doesn't.
	[Fact]
	async Task Two_factor_challenge_routes_through_deferred_completion_with_a_root_relative_return_url_when_stashed()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.TwoFactorRequired);
		var deferredSignIn = Substitute.For<IDeferredSignIn>();
		deferredSignIn.BuildCompletionUrl(Arg.Any<string>(), Arg.Any<string>())
			.Returns(call => $"/_auth/complete?key={call.ArgAt<string>(0)}&returnUrl={Uri.EscapeDataString(call.ArgAt<string>(1))}");
		DefaultHttpContext httpContext = new();
		httpContext.Items[NorseSignInManager.DeferredSignInKeyItemName] = "stashed-key";
		var handler = CreateHandler(signInManager, deferredSignIn, httpContext);
		LoginCommand command = new(new LoginRequest { Email = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LoginResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldContain("stashed-key");
		success.Value.NextUrl.ShouldContain(Uri.EscapeDataString("/Account/LoginWith2fa?RememberMe=false"));
		// The actual regression this guards: a path-relative returnUrl here would resolve, under RFC
		// 3986, against /_auth/complete by stripping its last segment -- landing at the nonexistent
		// /_auth/Account/LoginWith2fa instead of /Account/LoginWith2fa. Assert the escaped returnUrl
		// segment itself starts with a slash, not just that the route name is present somewhere.
		var returnUrlValue = success.Value.NextUrl![(success.Value.NextUrl.IndexOf("returnUrl=", StringComparison.Ordinal) + "returnUrl=".Length)..];
		Uri.UnescapeDataString(returnUrlValue).ShouldStartWith("/");
	}

	[Fact]
	async Task NextUrl_defaults_to_root_when_nothing_is_stashed_on_HttpContext()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Success);
		var handler = CreateHandler(signInManager);
		LoginCommand command = new(new LoginRequest { Email = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		// "/" is resolved here, server-side -- not left for the client to supply as its own default.
		outcome.TryGetValue(out Success<LoginResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldBe("/");
	}

	// A leading-slash NextUrl is only origin-absolute-correct when the origin's root really is the
	// app root -- under a non-root PathBase, a bare "/" or "/Account/LoginWith2fa" would escape the
	// app entirely once a client actually navigates there. NextUrl must carry the live request's
	// PathBase, the same way IdentityComponentsEndpointRouteBuilderExtensions already does for its
	// own redirects (UriHelper.BuildRelative), not hardcode root hosting.
	[Fact]
	async Task NextUrl_carries_the_request_s_PathBase_for_a_completed_sign_in()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Success);
		DefaultHttpContext httpContext = new();
		httpContext.Request.PathBase = "/example";
		var handler = CreateHandler(signInManager, httpContext: httpContext);
		LoginCommand command = new(new LoginRequest { Email = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LoginResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldBe("/example/");
	}

	[Fact]
	async Task NextUrl_carries_the_request_s_PathBase_for_the_two_factor_challenge()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.TwoFactorRequired);
		DefaultHttpContext httpContext = new();
		httpContext.Request.PathBase = "/example";
		var handler = CreateHandler(signInManager, httpContext: httpContext);
		LoginCommand command = new(new LoginRequest { Email = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LoginResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldBe("/example/Account/LoginWith2fa?RememberMe=false");
	}

	[Fact]
	async Task NextUrl_is_the_deferred_completion_url_when_one_is_stashed_on_HttpContext()
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
		success.Value.NextUrl.ShouldContain("stashed-key");
	}
}
