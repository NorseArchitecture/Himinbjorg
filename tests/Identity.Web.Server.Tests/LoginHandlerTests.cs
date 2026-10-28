using Microsoft.AspNetCore.Http;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
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
		return new LoginHandler(signInManager,
			new DeferredCompletion(deferredSignIn ?? Substitute.For<IDeferredSignIn>(), accessor), accessor);
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
		LoginCommand command = new(new LoginRequest { EmailInput = "user@example.com", Password = "wrong-password" });

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
		LoginCommand command = new(new LoginRequest { EmailInput = "user@example.com", Password = "wrong-password" });

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
		LoginCommand command = new(new LoginRequest { EmailInput = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<NavigationResult> _).ShouldBeTrue();
	}

	[Fact]
	async Task Wrong_credentials_produce_an_invalid_credentials_model_error()
	{
		var handler = NewHandlerWithFailingSignIn();
		LoginCommand command = new(new LoginRequest { EmailInput = "who@example.com", Password = "nope" });

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
			new(new LoginRequest { EmailInput = "ghost@example.com", Password = "x" }),
			TestContext.Current.CancellationToken);
		var wrongPasswordOutcome = await NewHandlerWithFailingSignIn().Handle(
			new(new LoginRequest { EmailInput = "real@example.com", Password = "x" }),
			TestContext.Current.CancellationToken);

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
	async Task
		Returns_the_two_factor_challenge_url_on_the_success_side_when_the_password_is_correct_but_2fa_is_pending()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.TwoFactorRequired);
		DefaultHttpContext httpContext = new();
		httpContext.Items[NorseSignInManager.TwoFactorChallengeItemName] = "tok";
		var handler = CreateHandler(signInManager, httpContext: httpContext);
		LoginCommand command = new(new LoginRequest { EmailInput = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		// The correct password must never route into the same branch a wrong password does -- that
		// would make a 2FA-enabled user's genuinely correct password indistinguishable from a failed
		// one, defeating the entire point of a second factor. The server resolves NextUrl to the full
		// navigation target itself -- the challenge token NorseSignInManager parked, carried on the
		// query -- so the client gets a concrete URL, never a flag to branch on or a route to build.
		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldBe("/Account/LoginWith2fa?challenge=tok");
	}

	[Fact]
	async Task A_two_factor_required_result_without_a_parked_token_throws()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.TwoFactorRequired);
		var handler = CreateHandler(signInManager);
		LoginCommand command = new(new LoginRequest { EmailInput = "user@example.com", Password = "correct-horse" });

		await Should.ThrowAsync<InvalidOperationException>(async () =>
			await handler.Handle(command, TestContext.Current.CancellationToken));
	}

	// Nothing is stashed on the two-factor branch -- NorseSignInManager parks a challenge token instead of
	// writing (or deferring) a partial cookie -- so the challenge URL is never a deferred-completion
	// returnUrl. An identity key on Items (which that branch never leaves) still must not pull it through
	// the detour: the assertion pins the absence of the call, not just the URL it would have produced.
	[Fact]
	async Task The_two_factor_branch_never_routes_through_deferred_completion()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.TwoFactorRequired);
		var deferredSignIn = Substitute.For<IDeferredSignIn>();
		DefaultHttpContext httpContext = new();
		httpContext.Items[NorseSignInManager.TwoFactorChallengeItemName] = "tok";
		httpContext.Items[NorseSignInManager.DeferredSignInKeyItemName] = "stashed-key";
		var handler = CreateHandler(signInManager, deferredSignIn, httpContext);
		LoginCommand command = new(new LoginRequest { EmailInput = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldBe("/Account/LoginWith2fa?challenge=tok");
		deferredSignIn.DidNotReceiveWithAnyArgs().BuildCompletionUrl(default!, default!);
	}

	[Fact]
	async Task NextUrl_defaults_to_root_when_nothing_is_stashed_on_HttpContext()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Success);
		var handler = CreateHandler(signInManager);
		LoginCommand command = new(new LoginRequest { EmailInput = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		// "/" is resolved here, server-side -- not left for the client to supply as its own default.
		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldBe("/");
	}

	// A leading-slash NextUrl is only origin-absolute-correct when the origin's root really is the
	// app root -- under a non-root PathBase, a bare "/" or "/Account/LoginWith2fa" would escape the
	// app entirely once a client actually navigates there. NextUrl must carry the live request's
	// PathBase, the same way ExternalLoginEndpointRouteBuilderExtensions already does for its
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
		LoginCommand command = new(new LoginRequest { EmailInput = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
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
		httpContext.Items[NorseSignInManager.TwoFactorChallengeItemName] = "tok";
		var handler = CreateHandler(signInManager, httpContext: httpContext);
		LoginCommand command = new(new LoginRequest { EmailInput = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldBe("/example/Account/LoginWith2fa?challenge=tok");
	}

	[Fact]
	async Task NextUrl_is_the_deferred_completion_url_when_one_is_stashed_on_HttpContext()
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Success);
		var deferredSignIn = Substitute.For<IDeferredSignIn>();
		deferredSignIn.BuildCompletionUrl(Arg.Any<string>(), Arg.Any<string>())
			.Returns(call =>
				$"/_auth/complete?key={call.ArgAt<string>(0)}&returnUrl={Uri.EscapeDataString(call.ArgAt<string>(1))}");
		DefaultHttpContext httpContext = new();
		httpContext.Items[NorseSignInManager.DeferredSignInKeyItemName] = "stashed-key";
		var handler = CreateHandler(signInManager, deferredSignIn, httpContext);
		LoginCommand command = new(new LoginRequest { EmailInput = "user@example.com", Password = "correct-horse" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldContain("stashed-key");
	}

	[Fact]
	async Task A_local_return_url_is_the_landing()
	{
		var nextUrl = await SignInWithReturnUrlAsync("/app/Account/Manage?x=1");

		nextUrl.ShouldBe("/app/Account/Manage?x=1");
	}

	[Fact]
	async Task A_foreign_return_url_lands_on_the_app_root()
	{
		var nextUrl = await SignInWithReturnUrlAsync("https://evil.example/");

		nextUrl.ShouldBe("/app/");
	}

	// The resolved landing is parked for the challenge mint only while PasswordSignInAsync runs, on every exit.
	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	async Task The_parked_item_is_removed_after_sign_in(bool succeeds)
	{
		var signInManager = MockSignInManager.Create();
		DefaultHttpContext httpContext = new();
		httpContext.Request.PathBase = "/app";
		object? parkedDuringSignIn = null;
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(_ =>
			{
				parkedDuringSignIn = httpContext.Items[NorseSignInManager.ReturnUrlItemName];
				return succeeds ?
					Microsoft.AspNetCore.Identity.SignInResult.Success :
					Microsoft.AspNetCore.Identity.SignInResult.Failed;
			});
		var handler = CreateHandler(signInManager, httpContext: httpContext);

		await handler.Handle(new(new LoginRequest
		{
			EmailInput = "user@example.com",
			Password = "correct-horse",
			ReturnUrl = "/app/Account/Manage"
		}), TestContext.Current.CancellationToken);

		parkedDuringSignIn.ShouldBe("/app/Account/Manage");
		httpContext.Items.ContainsKey(NorseSignInManager.ReturnUrlItemName).ShouldBeFalse();
	}

	static async Task<string> SignInWithReturnUrlAsync(string returnUrl)
	{
		var signInManager = MockSignInManager.Create();
		signInManager.PasswordSignInAsync("user@example.com", "correct-horse", false, true)
			.Returns(Microsoft.AspNetCore.Identity.SignInResult.Success);
		DefaultHttpContext httpContext = new();
		httpContext.Request.PathBase = "/app";
		var handler = CreateHandler(signInManager, httpContext: httpContext);

		var outcome = await handler.Handle(new(new LoginRequest
		{
			EmailInput = "user@example.com",
			Password = "correct-horse",
			ReturnUrl = returnUrl
		}), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		return success.Value.NextUrl;
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	async Task An_indeterminate_increment_or_a_destroyed_key_fails_closed_to_the_same_invalid_credentials_instance(
		bool indeterminate)
	{
		// Spec §4.5: an indeterminate access-failed increment fails sign-in closed, to LoginHandler's single static
		// Failed. A key destroyed mid-erasure (spec §5) answers the same: an erased account is indistinguishable from
		// bad credentials.
		var signInManager = MockSignInManager.Create();
		Exception thrown = indeterminate ?
			new IndeterminateWriteException("the increment", new TimeoutException()) :
			new KeyDestroyedException(new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch));
		signInManager.PasswordSignInAsync(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<bool>(), Arg.Any<bool>())
			.ThrowsAsync(thrown);
		var reference = await NewHandlerWithFailingSignIn().Handle(
			new(new LoginRequest { EmailInput = "real@example.com", Password = "x" }),
			TestContext.Current.CancellationToken);

		var outcome = await CreateHandler(signInManager).Handle(
			new(new LoginRequest { EmailInput = "real@example.com", Password = "x" }),
			TestContext.Current.CancellationToken);

		reference.TryGetValue(out Failed expected).ShouldBeTrue();
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.ShouldBeSameAs(expected.Problem);
	}
}
