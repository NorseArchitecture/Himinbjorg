using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.SignInMethods;
using Norse.Identity.Web.Server.Tests.Passkeys;

namespace Norse.Identity.Web.Server.Tests.SignInMethods;

/// <summary>
///     <see cref="PasskeySignInHandler" />, over a real <see cref="NorseSignInManager" /> on <see cref="TwoFactorHarness" />:
///     the landing is only what <see cref="ReturnUrls.Resolve" /> decides, every credential refusal collapses onto one
///     static instance, a lockout keeps its own text, and a two-factor account signs in without the challenge (the
///     recorded <c>bypassTwoFactor: true</c>, ruled binding: a user-verified passkey is itself multi-factor).
/// </summary>
public sealed class PasskeySignInHandlerTests
{
	const string RawState = "{\"challenge\":\"handler-state\",\"userId\":null}";

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task A_local_return_url_is_the_landing()
	{
		using var harness = await StartAsync();

		var direct = await HandleAsync(harness, Protect(harness, "direct"), "/Account/Manage?tab=1#top");
		harness.DeferredSignIn
			.StashSignIn(Arg.Any<string>(), Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>())
			.Returns("stash-key");
		harness.DeferredSignIn.BuildCompletionUrl("stash-key", "/Account/Manage").Returns("/_auth/complete?key=stash-key");
		var circuit = await HandleAsync(harness, Protect(harness, "circuit"), "/Account/Manage",
			responseAlreadyStarted: true);

		BaseRequest.ValueOf(direct).NextUrl.ShouldBe("/Account/Manage?tab=1#top");
		BaseRequest.ValueOf(circuit).NextUrl.ShouldBe("/_auth/complete?key=stash-key",
			"a circuit's stashed sign-in completes through the deferred landing");
	}

	[Theory]
	[InlineData("https://evil.example/")]
	[InlineData("//evil.example")]
	[InlineData("/\\evil.example")]
	[InlineData("javascript:alert(1)")]
	[InlineData("")]
	async Task A_foreign_return_url_lands_on_the_app_root(string returnUrl)
	{
		using var harness = await StartAsync();

		var outcome = await HandleAsync(harness, Protect(harness, returnUrl), returnUrl);

		BaseRequest.ValueOf(outcome).NextUrl.ShouldBe("/");
	}

	[Fact]
	async Task A_failed_assertion_answers_the_static_instance()
	{
		using var harness = await StartAsync();
		harness.PasskeyHandler.PerformAssertionAsync(Arg.Is<PasskeyAssertionContext>(c => c.CredentialJson == "bad"))
			.Returns(PasskeyAssertionResult.Fail<NorseUser>(new PasskeyException("The origin 'https://evil.example' is not allowed.")));
		var replayed = Protect(harness, "replayed");
		await HandleAsync(harness, replayed, "/");

		var refused = BaseRequest.ProblemOf(await HandleAsync(harness, Protect(harness, "refused"), "/", "bad"));
		var replay = BaseRequest.ProblemOf(await HandleAsync(harness, replayed, "/"));
		var tampered = BaseRequest.ProblemOf(await HandleAsync(harness, "not a protected state", "/"));

		refused.Errors.Values.SelectMany(static messages => messages)
			.ShouldBe(["The passkey could not be used to sign in."], "the handler's own message never leaves the server");
		replay.ShouldBeSameAs(refused, "every credential refusal is the one static instance");
		tampered.ShouldBeSameAs(refused);
	}

	[Fact]
	async Task A_locked_out_account_answers_the_locked_out_message()
	{
		using var harness = await StartAsync();
		harness.UserManager.IsLockedOutAsync(harness.User).Returns(true);

		var problem = BaseRequest.ProblemOf(await HandleAsync(harness, Protect(harness, "locked"), "/"));

		problem.Category.ShouldBe(ErrorCategory.LockedOut);
		problem.Errors[""].ShouldBe(["This account is locked out. Try again later or reset your password."]);
	}

	[Fact]
	async Task A_two_factor_account_signs_in_without_the_challenge()
	{
		using var harness = await StartAsync();
		(await harness.UserManager.GetTwoFactorEnabledAsync(harness.User)).ShouldBeTrue();

		var outcome = await HandleAsync(harness, Protect(harness, "two-factor"), "/Account/Manage");

		BaseRequest.ValueOf(outcome).NextUrl.ShouldBe("/Account/Manage", "no challenge URL: the passkey bypasses it");
	}

	static async Task<TwoFactorHarness> StartAsync()
	{
		var harness = await TwoFactorHarness.StartAsync();
		harness.PasskeyHandler.PerformAssertionAsync(Arg.Any<PasskeyAssertionContext>())
			.Returns(PasskeyAssertionResult.Success(TestPasskeys.Info([0x0A]), harness.User));
		return harness;
	}

	// A distinct raw state per call: the ledger is one-shot over the unprotected state.
	static string Protect(TwoFactorHarness harness, string discriminator) =>
		harness.AssertionProtector.Protect(RawState.Replace("handler-state", $"handler-state-{discriminator}",
			StringComparison.Ordinal), TimeSpan.FromMinutes(5));

	static async Task<Outcome<NavigationResult>> HandleAsync(TwoFactorHarness harness, string state, string returnUrl,
		string credentialJson = "good", bool responseAlreadyStarted = false) =>
		(await harness.RunAsync(manager =>
		{
			var accessor = Substitute.For<IHttpContextAccessor>();
			accessor.HttpContext.Returns(manager.Context);
			PasskeySignInHandler handler = new(manager, new DeferredCompletion(harness.DeferredSignIn, accessor), accessor);
			return handler.Handle(new(new PasskeySignInRequest
			{
				CredentialJson = credentialJson,
				AssertionState = state,
				ReturnUrl = returnUrl
			}), Cancellation).AsTask();
		}, responseAlreadyStarted)).Value.ShouldNotBeNull();
}
