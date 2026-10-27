using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     <see cref="TwoFactorSignInHandler" /> over a real <see cref="NorseSignInManager" /> on
///     <see cref="TwoFactorHarness" />: a genuine challenge token is parked by a password sign-in, then redeemed by the
///     handler inside one real request.
/// </summary>
public sealed class TwoFactorSignInHandlerTests
{
	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Success_answers_the_app_root()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = await ParkChallengeAsync(harness);

		var probe = await SignInAsync(harness, token, TwoFactorHarness.AuthenticatorCode);

		NextUrlOf(probe.Value).ShouldBe("/");
	}

	[Fact]
	async Task Success_on_a_circuit_answers_the_deferred_completion_url()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		StubDeferredSignIn(harness);
		var token = await ParkChallengeAsync(harness);

		var probe = await SignInAsync(harness, token, TwoFactorHarness.AuthenticatorCode, responseAlreadyStarted: true);

		probe.IdentityKey.ShouldBe(KeyFor(IdentityConstants.ApplicationScheme));
		probe.RememberKey.ShouldBeNull();
		NextUrlOf(probe.Value).ShouldBe(harness.DeferredSignIn.BuildCompletionUrl(probe.IdentityKey!, "/"));
	}

	[Fact]
	async Task Both_stashes_produce_the_chained_url()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		StubDeferredSignIn(harness);
		var token = await ParkChallengeAsync(harness);

		var probe = await SignInAsync(harness, token, TwoFactorHarness.AuthenticatorCode, rememberMachine: true,
			responseAlreadyStarted: true);

		probe.IdentityKey.ShouldBe(KeyFor(IdentityConstants.ApplicationScheme));
		probe.RememberKey.ShouldBe(KeyFor(IdentityConstants.TwoFactorRememberMeScheme));
		// The identity completion runs outermost; the remember completion, inside it, lands on the app root.
		var expected = harness.DeferredSignIn.BuildCompletionUrl(probe.IdentityKey!,
			harness.DeferredSignIn.BuildCompletionUrl(probe.RememberKey!, "/"));
		var nextUrl = NextUrlOf(probe.Value);
		nextUrl.ShouldBe(expected);
		nextUrl.ShouldStartWith($"/_auth/complete?key={probe.IdentityKey}&");
		nextUrl.ShouldContain("%252F");
	}

	[Fact]
	async Task Every_refusal_collapses_onto_the_handlers_one_static_instance()
	{
		using var harness = await TwoFactorHarness.StartAsync();

		var wrongCodeToken = await ParkChallengeAsync(harness);
		var wrongCode = await SignInAsync(harness, wrongCodeToken, "000000");

		var rotatedToken = await ParkChallengeAsync(harness);
		harness.Stamp = Guid.NewGuid().ToString();
		var stampMismatch = await SignInAsync(harness, rotatedToken, TwoFactorHarness.AuthenticatorCode);

		var erasedToken = await ParkChallengeAsync(harness);
		harness.UserManager.FindByIdAsync(harness.UserId)
			.ThrowsAsync(new KeyDestroyedException(new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch)));
		var erased = await SignInAsync(harness, erasedToken, TwoFactorHarness.AuthenticatorCode);

		var first = ProblemOf(wrongCode.Value);
		ProblemOf(stampMismatch.Value).ShouldBeSameAs(first);
		ProblemOf(erased.Value).ShouldBeSameAs(first);
		first.Category.ShouldBe(ErrorCategory.InvalidCredentials);
		first.Errors.Keys.ShouldBe([string.Empty]);
		first.Errors[string.Empty].ShouldBe(["Invalid authenticator code."]);
	}

	[Fact]
	async Task LockedOut_carries_its_text()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = await ParkChallengeAsync(harness);
		var lockedOut = false;
		harness.UserManager.AccessFailedAsync(harness.User).Returns(_ =>
		{
			lockedOut = true;
			return IdentityResult.Success;
		});
		harness.UserManager.IsLockedOutAsync(harness.User).Returns(_ => lockedOut);

		var probe = await SignInAsync(harness, token, "000000");

		var problem = ProblemOf(probe.Value);
		problem.Category.ShouldBe(ErrorCategory.LockedOut);
		problem.Errors[string.Empty].ShouldBe(["This account is locked out. Try again later or reset your password."]);
	}

	static string KeyFor(string scheme) =>
		$"stashed-{scheme}";

	// Each scheme stashes under its own key, and the completion URL escapes its return URL the way Midgard's does.
	static void StubDeferredSignIn(TwoFactorHarness harness)
	{
		harness.DeferredSignIn
			.StashSignIn(Arg.Any<string>(), Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>())
			.Returns(call => KeyFor(call.ArgAt<string>(0)));
		harness.DeferredSignIn.BuildCompletionUrl(Arg.Any<string>(), Arg.Any<string>())
			.Returns(call =>
				$"/_auth/complete?key={call.ArgAt<string>(0)}&returnUrl={Uri.EscapeDataString(call.ArgAt<string>(1))}");
	}

	static async Task<string> ParkChallengeAsync(TwoFactorHarness harness) =>
		(await harness.RunAsync(manager => manager.PasswordSignInAsync(harness.User, TwoFactorHarness.Password,
			isPersistent: false, lockoutOnFailure: false))).Token.ShouldNotBeNull();

	static Task<TwoFactorHarness.Probe<Outcome<NavigationResult>>> SignInAsync(TwoFactorHarness harness, string token,
		string code, bool rememberMachine = false, bool responseAlreadyStarted = false) =>
		harness.RunAsync(manager =>
		{
			var accessor = harness.Services.GetRequiredService<IHttpContextAccessor>();
			TwoFactorSignInHandler handler = new(manager, new(harness.DeferredSignIn, accessor), accessor);
			return handler.Handle(new(new TwoFactorSignInRequest
			{
				Challenge = token,
				Code = code,
				RememberMachine = rememberMachine
			}), Cancellation).AsTask();
		}, responseAlreadyStarted);

	static string NextUrlOf(Outcome<NavigationResult>? outcome)
	{
		outcome.ShouldNotBeNull().TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		return success.Value.NextUrl;
	}

	static Problem ProblemOf(Outcome<NavigationResult>? outcome)
	{
		outcome.ShouldNotBeNull().TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem;
	}
}
