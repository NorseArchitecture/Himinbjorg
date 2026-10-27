using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     Proves <see cref="NorseSignInManager" /> actually intercepts sign-in/sign-out once
///     <c>HttpContext.Response.HasStarted</c> is genuinely true (an already-established Blazor Server
///     interactive circuit), behaves exactly like the unmodified base class otherwise, and carries the
///     two-factor challenge as a protected token rather than the framework's partial cookie.
///     "Genuinely true" is not simulated via reflection or a hand-rolled fake -- these tests host a real,
///     minimal ASP.NET Core pipeline via <see cref="TestServer" /> with real cookie authentication handlers
///     wired in. Writing to the response body before sign-in flips <c>HasStarted</c> for real, the same way
///     Kestrel does, and the unmodified <see cref="SignInManager{TUser}" /> genuinely throws
///     <see cref="InvalidOperationException" /> trying to write the Set-Cookie header afterward.
/// </summary>
public sealed class NorseSignInManagerTests
{
	const string StashedSignInKey = "stashed-sign-in-key";
	const string StashedSignOutKey = "stashed-sign-out-key";
	const string WrongAuthenticatorCode = "000000";
	const string WrongRecoveryCode = "wrong-code";
	static readonly string _scheme = IdentityConstants.ApplicationScheme;
	static readonly string _rememberMeScheme = IdentityConstants.TwoFactorRememberMeScheme;

	[Fact]
	async Task Unmodified_SignInManager_throws_once_the_response_has_already_started()
	{
		var probe = await RunAsync(false, true, false);

		probe.Exception.ShouldNotBeNull();
		probe.Exception.ShouldBeOfType<InvalidOperationException>();
	}

	[Fact]
	async Task Unmodified_SignInManager_signs_out_directly_and_throws_once_the_response_has_already_started()
	{
		var probe = await RunAsync(false, true, true);

		probe.Exception.ShouldNotBeNull();
		probe.Exception.ShouldBeOfType<InvalidOperationException>();
	}

	[Fact]
	async Task NorseSignInManager_defers_sign_in_once_the_response_has_already_started()
	{
		var probe = await RunAsync(true, true, false);

		probe.Exception.ShouldBeNull();
		probe.DeferredSignIn.Received(1)
			.StashSignIn(_scheme, Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>());
		probe.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignOut(default!);
		probe.ItemsKey.ShouldBe(StashedSignInKey);
	}

	[Fact]
	async Task NorseSignInManager_defers_sign_out_once_the_response_has_already_started()
	{
		var probe = await RunAsync(true, true, true);

		probe.Exception.ShouldBeNull();
		probe.DeferredSignIn.Received(1).StashSignOut(_scheme);
		probe.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignIn(default!, default!, default!);
		probe.ItemsKey.ShouldBe(StashedSignOutKey);
	}

	[Fact]
	async Task NorseSignInManager_signs_in_directly_when_the_response_has_not_started()
	{
		var probe = await RunAsync(true, false, false);

		probe.Exception.ShouldBeNull();
		probe.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignIn(default!, default!, default!);
		probe.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignOut(default!);
		probe.ItemsKey.ShouldBeNull();
		probe.SetCookieHeaderPresent.ShouldBeTrue();
	}

	[Fact]
	async Task NorseSignInManager_signs_out_directly_when_the_response_has_not_started()
	{
		var probe = await RunAsync(true, false, true);

		probe.Exception.ShouldBeNull();
		probe.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignIn(default!, default!, default!);
		probe.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignOut(default!);
		probe.ItemsKey.ShouldBeNull();
		probe.SetCookieHeaderPresent.ShouldBeTrue();
	}

	// The real, unmodified SignInManager<TUser>.SignInOrTwoFactorAsync (ilspycmd decompile of the installed
	// Microsoft.AspNetCore.Identity assembly, .NET 11 RC3, 2026-10-26) writes the partial two-factor cookie via
	// a raw Context.SignInAsync(TwoFactorUserIdScheme, ...) call that funnels through no overridable seam at
	// all. On an established circuit that throws before SignInResult.TwoFactorRequired is ever returned --
	// the reason NorseSignInManager carries the challenge as a token instead of a cookie.
	[Fact]
	async Task Unmodified_SignInManager_throws_writing_the_two_factor_cookie_once_the_response_has_already_started()
	{
		var probe = await RunUnmodifiedTwoFactorAsync();

		probe.Exception.ShouldNotBeNull();
		probe.Exception.ShouldBeOfType<InvalidOperationException>();
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	async Task A_two_factor_required_sign_in_parks_a_token_and_writes_no_cookie(bool responseAlreadyStarted)
	{
		using var harness = await TwoFactorHarness.StartAsync();

		var probe = await harness.RunAsync(PasswordSignInAsync(harness), responseAlreadyStarted);

		probe.Exception.ShouldBeNull();
		probe.Value.ShouldBe(SignInResult.TwoFactorRequired);
		probe.Token.ShouldNotBeNull();
		probe.SetCookieHeaderPresent.ShouldBeFalse();
		probe.IdentityKey.ShouldBeNull();
		harness.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignIn(default!, default!, default!);
		harness.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignOut(default!);
	}

	[Fact]
	async Task A_parked_token_unprotects_to_the_user_id_stamp_persistence_and_provider()
	{
		using var harness = await TwoFactorHarness.StartAsync();

		var external = await harness.RunAsync(manager => manager.ExternalLoginSignInAsync(
			TwoFactorHarness.ExternalProvider, TwoFactorHarness.ExternalProviderKey, isPersistent: true,
			bypassTwoFactor: false));
		var password = await harness.RunAsync(PasswordSignInAsync(harness));

		TwoFactorChallenge.TryUnprotect(harness.ChallengeProtector, external.Token!, out var externalChallenge)
			.ShouldBeTrue();
		externalChallenge.ShouldBe(new(harness.UserId, harness.Stamp, IsPersistent: true,
			TwoFactorHarness.ExternalProvider));
		TwoFactorChallenge.TryUnprotect(harness.ChallengeProtector, password.Token!, out var passwordChallenge)
			.ShouldBeTrue();
		passwordChallenge.ShouldBe(new(harness.UserId, harness.Stamp, IsPersistent: false, LoginProvider: null));
	}

	[Fact]
	async Task A_correct_authenticator_code_completes_the_sign_in_with_amr_mfa()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = (await harness.RunAsync(PasswordSignInAsync(harness, isPersistent: true))).Token!;

		var probe = await harness.RunAsync(manager =>
			manager.TwoFactorChallengeSignInAsync(token, TwoFactorHarness.AuthenticatorCode, rememberClient: false));

		probe.Exception.ShouldBeNull();
		probe.Value.ShouldBe(SignInResult.Success);
		var ticket = harness.Decrypt(_scheme, probe.SetCookieFor(".AspNetCore.Identity.Application")!);
		ticket.Principal.FindFirstValue("amr").ShouldBe("mfa");
		ticket.Principal.HasClaim(claim => claim.Type == ClaimTypes.AuthenticationMethod).ShouldBeFalse();
		ticket.Properties.IsPersistent.ShouldBeTrue();
		probe.SetCookieFor(_rememberMeScheme).ShouldBeNull();
	}

	[Fact]
	async Task A_correct_authenticator_code_resets_the_failed_count_before_signing_in()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = (await harness.RunAsync(PasswordSignInAsync(harness))).Token!;

		var probe = await harness.RunAsync(manager =>
			manager.TwoFactorChallengeSignInAsync(token, TwoFactorHarness.AuthenticatorCode, rememberClient: false));

		probe.Value.ShouldBe(SignInResult.Success);
		await harness.UserManager.Received(1).ResetAccessFailedCountAsync(harness.User);
		// The principal is built inside SignInWithClaimsAsync, so the reset preceding it is the reset preceding the sign-in.
		Received.InOrder(async () =>
		{
			await harness.UserManager.ResetAccessFailedCountAsync(harness.User);
			await harness.ClaimsFactory.CreateAsync(harness.User);
		});
	}

	[Fact]
	async Task A_correct_recovery_code_resets_the_failed_count_before_signing_in()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = (await harness.RunAsync(PasswordSignInAsync(harness))).Token!;

		var probe = await harness.RunAsync(manager =>
			manager.RecoveryCodeChallengeSignInAsync(token, TwoFactorHarness.RecoveryCode));

		probe.Value.ShouldBe(SignInResult.Success);
		await harness.UserManager.Received(1).ResetAccessFailedCountAsync(harness.User);
		Received.InOrder(async () =>
		{
			await harness.UserManager.ResetAccessFailedCountAsync(harness.User);
			await harness.ClaimsFactory.CreateAsync(harness.User);
		});
	}

	[Theory]
	[InlineData("Failed")]
	[InlineData("IndeterminateOutcome")]
	async Task A_failed_or_indeterminate_lockout_reset_refuses_the_authenticator_sign_in_and_issues_nothing(
		string resultKind)
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = (await harness.RunAsync(PasswordSignInAsync(harness))).Token!;
		harness.UserManager.ResetAccessFailedCountAsync(harness.User).Returns(LockoutResetFailure(resultKind));

		var probe = await harness.RunAsync(manager =>
			manager.TwoFactorChallengeSignInAsync(token, TwoFactorHarness.AuthenticatorCode, rememberClient: true));

		probe.Exception.ShouldBeNull();
		probe.Value.ShouldBe(SignInResult.Failed);
		probe.SetCookieHeaderPresent.ShouldBeFalse();
		harness.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignIn(default!, default!, default!);
		await harness.ClaimsFactory.DidNotReceiveWithAnyArgs().CreateAsync(default!);
	}

	[Theory]
	[InlineData("Failed")]
	[InlineData("IndeterminateOutcome")]
	async Task A_failed_or_indeterminate_lockout_reset_refuses_the_recovery_code_sign_in_and_issues_nothing(
		string resultKind)
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = (await harness.RunAsync(PasswordSignInAsync(harness))).Token!;
		harness.UserManager.ResetAccessFailedCountAsync(harness.User).Returns(LockoutResetFailure(resultKind));

		var probe = await harness.RunAsync(manager =>
			manager.RecoveryCodeChallengeSignInAsync(token, TwoFactorHarness.RecoveryCode));

		probe.Exception.ShouldBeNull();
		probe.Value.ShouldBe(SignInResult.Failed);
		probe.SetCookieHeaderPresent.ShouldBeFalse();
		harness.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignIn(default!, default!, default!);
		await harness.ClaimsFactory.DidNotReceiveWithAnyArgs().CreateAsync(default!);
	}

	[Fact]
	async Task A_wrong_code_counts_toward_lockout_and_answers_LockedOut_when_it_trips()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = (await harness.RunAsync(PasswordSignInAsync(harness))).Token!;
		var lockedOut = false;
		harness.UserManager.AccessFailedAsync(harness.User).Returns(_ =>
		{
			lockedOut = true;
			return IdentityResult.Success;
		});
		harness.UserManager.IsLockedOutAsync(harness.User).Returns(_ => lockedOut);

		var probe = await harness.RunAsync(manager =>
			manager.TwoFactorChallengeSignInAsync(token, WrongAuthenticatorCode, rememberClient: false));

		probe.Value.ShouldBe(SignInResult.LockedOut);
		await harness.UserManager.Received(1).AccessFailedAsync(harness.User);
		probe.SetCookieHeaderPresent.ShouldBeFalse();
	}

	[Fact]
	async Task A_challenge_issued_before_a_stamp_rotation_is_refused_on_the_authenticator_path()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = (await harness.RunAsync(PasswordSignInAsync(harness))).Token!;
		harness.Stamp = Guid.NewGuid().ToString();

		var probe = await harness.RunAsync(manager =>
			manager.TwoFactorChallengeSignInAsync(token, TwoFactorHarness.AuthenticatorCode, rememberClient: false));

		probe.Value.ShouldBe(SignInResult.Failed);
		await harness.UserManager.DidNotReceiveWithAnyArgs().VerifyTwoFactorTokenAsync(default!, default!, default!);
		probe.SetCookieHeaderPresent.ShouldBeFalse();
	}

	[Fact]
	async Task A_challenge_issued_before_a_stamp_rotation_is_refused_on_the_recovery_code_path()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = (await harness.RunAsync(PasswordSignInAsync(harness))).Token!;
		harness.Stamp = Guid.NewGuid().ToString();

		var probe = await harness.RunAsync(manager =>
			manager.RecoveryCodeChallengeSignInAsync(token, TwoFactorHarness.RecoveryCode));

		probe.Value.ShouldBe(SignInResult.Failed);
		await harness.UserManager.DidNotReceiveWithAnyArgs().RedeemTwoFactorRecoveryCodeAsync(default!, default!);
		probe.SetCookieHeaderPresent.ShouldBeFalse();
	}

	[Fact]
	async Task A_recovery_code_completes_a_non_persistent_sign_in_and_never_counts_toward_lockout()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = (await harness.RunAsync(PasswordSignInAsync(harness, isPersistent: true))).Token!;
		harness.UserManager.RedeemTwoFactorRecoveryCodeAsync(harness.User, WrongRecoveryCode)
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().RecoveryCodeRedemptionFailed()));

		var wrong = await harness.RunAsync(manager => manager.RecoveryCodeChallengeSignInAsync(token, WrongRecoveryCode));
		var right = await harness.RunAsync(manager =>
			manager.RecoveryCodeChallengeSignInAsync(token, TwoFactorHarness.RecoveryCode));

		wrong.Value.ShouldBe(SignInResult.Failed);
		wrong.SetCookieHeaderPresent.ShouldBeFalse();
		await harness.UserManager.DidNotReceiveWithAnyArgs().AccessFailedAsync(default!);
		right.Value.ShouldBe(SignInResult.Success);
		var ticket = harness.Decrypt(_scheme, right.SetCookieFor(".AspNetCore.Identity.Application")!);
		ticket.Properties.IsPersistent.ShouldBeFalse();
		ticket.Principal.FindFirstValue("amr").ShouldBe("mfa");
		right.SetCookieFor(_rememberMeScheme).ShouldBeNull();
	}

	[Fact]
	async Task A_garbage_token_is_refused_without_throwing()
	{
		using var harness = await TwoFactorHarness.StartAsync();

		var authenticator = await harness.RunAsync(manager =>
			manager.TwoFactorChallengeSignInAsync("not a token!", TwoFactorHarness.AuthenticatorCode, rememberClient: false));
		var recovery = await harness.RunAsync(manager =>
			manager.RecoveryCodeChallengeSignInAsync("not a token!", TwoFactorHarness.RecoveryCode));

		authenticator.Exception.ShouldBeNull();
		authenticator.Value.ShouldBe(SignInResult.Failed);
		recovery.Exception.ShouldBeNull();
		recovery.Value.ShouldBe(SignInResult.Failed);
		await harness.UserManager.DidNotReceiveWithAnyArgs().FindByIdAsync(default!);
	}

	// The view folds the exception to Erased (Task 4.5) and the handler collapses Erased onto bad credentials
	// (Task 4.6); the manager itself lets the shredded key surface.
	[Fact]
	async Task A_challenge_for_an_erased_user_lets_the_destroyed_key_surface()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = (await harness.RunAsync(PasswordSignInAsync(harness))).Token!;
		harness.UserManager.FindByIdAsync(harness.UserId)
			.ThrowsAsync(new KeyDestroyedException(new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch)));

		var authenticator = await harness.RunAsync(manager =>
			manager.TwoFactorChallengeSignInAsync(token, TwoFactorHarness.AuthenticatorCode, rememberClient: false));
		var recovery = await harness.RunAsync(manager =>
			manager.RecoveryCodeChallengeSignInAsync(token, TwoFactorHarness.RecoveryCode));

		authenticator.Exception.ShouldBeOfType<KeyDestroyedException>();
		recovery.Exception.ShouldBeOfType<KeyDestroyedException>();
	}

	[Fact]
	async Task Spaces_and_hyphens_are_stripped_before_verification()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = (await harness.RunAsync(PasswordSignInAsync(harness))).Token!;

		var authenticator = await harness.RunAsync(manager =>
			manager.TwoFactorChallengeSignInAsync(token, " 123 - 456 ", rememberClient: false));
		var recovery = await harness.RunAsync(manager =>
			manager.RecoveryCodeChallengeSignInAsync(token, $" {TwoFactorHarness.RecoveryCode} "));

		authenticator.Value.ShouldBe(SignInResult.Success);
		await harness.UserManager.Received(1).VerifyTwoFactorTokenAsync(harness.User,
			TokenOptions.DefaultAuthenticatorProvider, TwoFactorHarness.AuthenticatorCode);
		recovery.Value.ShouldBe(SignInResult.Success);
		await harness.UserManager.Received(1)
			.RedeemTwoFactorRecoveryCodeAsync(harness.User, TwoFactorHarness.RecoveryCode);
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	async Task Remember_client_writes_directly_or_stashes_under_the_remember_me_scheme(bool responseAlreadyStarted)
	{
		using var harness = await TwoFactorHarness.StartAsync();
		harness.DeferredSignIn
			.StashSignIn(Arg.Any<string>(), Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>())
			.Returns(StashedSignInKey);

		var probe = await harness.RunAsync(manager => manager.RememberTwoFactorClientAsync(harness.User),
			responseAlreadyStarted);

		probe.Exception.ShouldBeNull();
		probe.IdentityKey.ShouldBeNull();
		if (responseAlreadyStarted)
		{
			probe.RememberKey.ShouldBe(StashedSignInKey);
			harness.DeferredSignIn.Received(1).StashSignIn(_rememberMeScheme, Arg.Any<ClaimsPrincipal>(),
				Arg.Is<AuthenticationProperties>(properties => properties.IsPersistent));
		}
		else
		{
			probe.RememberKey.ShouldBeNull();
			probe.SetCookieFor(_rememberMeScheme).ShouldNotBeNull();
			harness.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignIn(default!, default!, default!);
		}
	}

	[Fact]
	async Task The_deferred_remember_client_principal_carries_the_same_claims_as_the_direct_cookie()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		harness.DeferredSignIn
			.StashSignIn(Arg.Any<string>(), Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>())
			.Returns(StashedSignInKey);

		var direct = await harness.RunAsync(manager => manager.RememberTwoFactorClientAsync(harness.User));
		await harness.RunAsync(manager => manager.RememberTwoFactorClientAsync(harness.User), responseAlreadyStarted: true);

		var cookiePrincipal = harness.Decrypt(_rememberMeScheme, direct.SetCookieFor(_rememberMeScheme)!).Principal;
		var stashedPrincipal = (ClaimsPrincipal)harness.DeferredSignIn.ReceivedCalls()
			.Single(call => call.GetMethodInfo().Name == nameof(IDeferredSignIn.StashSignIn))
			.GetArguments()[1]!;
		foreach (var principal in new[] { cookiePrincipal, stashedPrincipal })
		{
			principal.Identity!.AuthenticationType.ShouldBe(_rememberMeScheme);
			principal.Claims.Select(claim => (claim.Type, claim.Value)).ShouldBe(
			[
				(ClaimTypes.Name, harness.UserId),
				(harness.SecurityStampClaimType, harness.Stamp)
			], ignoreOrder: true);
		}
	}

	[Fact]
	async Task A_stashed_remember_client_cookie_is_honored_until_the_stamp_rotates_and_the_validation_interval_elapses()
	{
		var rotated = await RunRememberedClientScenarioAsync(rotateStamp: true);
		var control = await RunRememberedClientScenarioAsync(rotateStamp: false);

		rotated.Value.ShouldBeFalse();
		rotated.SetCookieFor(_rememberMeScheme).ShouldNotBeNull().ShouldStartWith($"{_rememberMeScheme}=;");
		control.Value.ShouldBeTrue();
		control.SetCookieFor(_rememberMeScheme).ShouldBeNull();
	}

	[Fact]
	async Task A_remember_client_cookie_is_honored_on_a_started_response_until_the_stamp_rotates_and_the_interval_elapses()
	{
		var rotated = await RunRememberedClientScenarioAsync(rotateStamp: true, responseAlreadyStarted: true);
		var control = await RunRememberedClientScenarioAsync(rotateStamp: false, responseAlreadyStarted: true);

		rotated.Exception.ShouldBeNull();
		rotated.Value.ShouldBeFalse();
		rotated.SetCookieHeaderPresent.ShouldBeFalse();
		control.Exception.ShouldBeNull();
		control.Value.ShouldBeTrue();
	}

	[Fact]
	async Task A_missing_or_garbage_remember_client_cookie_answers_false_on_a_started_response()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		Func<NorseSignInManager, Task<bool>> remembered = manager => manager.IsTwoFactorClientRememberedAsync(harness.User);

		var missing = await harness.RunAsync(remembered, responseAlreadyStarted: true);
		var garbage = await harness.RunAsync(remembered, responseAlreadyStarted: true,
			cookie: $"{_rememberMeScheme}=not-a-ticket!");

		missing.Exception.ShouldBeNull();
		missing.Value.ShouldBeFalse();
		garbage.Exception.ShouldBeNull();
		garbage.Value.ShouldBeFalse();
	}

	[Fact]
	async Task An_expired_remember_me_cookie_is_not_honored_on_a_started_response()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var remembered = await harness.RunAsync(manager => manager.RememberTwoFactorClientAsync(harness.User));
		var cookie = TwoFactorHarness.CookieOf(remembered.SetCookieFor(_rememberMeScheme)!);
		Func<NorseSignInManager, Task<bool>> isRemembered =
			manager => manager.IsTwoFactorClientRememberedAsync(harness.User);
		(await harness.RunAsync(isRemembered, responseAlreadyStarted: true, cookie)).Value.ShouldBeTrue();

		// Past the remember-me ticket's stock 14-day lifetime; the stamp is untouched, so only expiry can refuse it.
		harness.Clock.Advance(TimeSpan.FromDays(15));
		var probe = await harness.RunAsync(isRemembered, responseAlreadyStarted: true, cookie);

		probe.Exception.ShouldBeNull();
		probe.Value.ShouldBeFalse();
	}

	[Fact]
	async Task Another_users_remember_me_cookie_is_not_honored_on_a_started_response()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		NorseUser other = new() { Id = Guid.NewGuid(), UserName = "other@example.com", Email = "other@example.com" };
		harness.UserManager.GetUserIdAsync(other).Returns(other.Id.ToString());
		harness.UserManager.GetSecurityStampAsync(other).Returns(_ => harness.Stamp);
		var remembered = await harness.RunAsync(manager => manager.RememberTwoFactorClientAsync(harness.User));
		var cookie = TwoFactorHarness.CookieOf(remembered.SetCookieFor(_rememberMeScheme)!);

		var owner = await harness.RunAsync(manager => manager.IsTwoFactorClientRememberedAsync(harness.User),
			responseAlreadyStarted: true, cookie);
		var probe = await harness.RunAsync(manager => manager.IsTwoFactorClientRememberedAsync(other),
			responseAlreadyStarted: true, cookie);

		other.Id.ToString().ShouldNotBe(harness.UserId);
		owner.Value.ShouldBeTrue();
		probe.Exception.ShouldBeNull();
		probe.Value.ShouldBeFalse();
	}

	// The base's own password step (CheckPasswordSignInCoreAsync) asks IsTwoFactorClientRememberedAsync before
	// SignInOrTwoFactorAsync ever runs; on a circuit that used to throw out of the cookie handler.
	[Fact]
	async Task A_remembered_client_bypasses_two_factor_on_a_started_response()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		harness.DeferredSignIn
			.StashSignIn(Arg.Any<string>(), Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>())
			.Returns(StashedSignInKey);
		var remembered = await harness.RunAsync(manager => manager.RememberTwoFactorClientAsync(harness.User));
		var cookie = TwoFactorHarness.CookieOf(remembered.SetCookieFor(_rememberMeScheme)!);

		var probe = await harness.RunAsync(PasswordSignInAsync(harness), responseAlreadyStarted: true, cookie);

		probe.Exception.ShouldBeNull();
		probe.Value.ShouldBe(SignInResult.Success);
		probe.Token.ShouldBeNull();
		probe.IdentityKey.ShouldBe(StashedSignInKey);
		harness.DeferredSignIn.Received(1)
			.StashSignIn(_scheme, Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>());
	}

	[Fact]
	async Task Forget_client_stashes_a_sign_out_once_the_response_has_started()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		harness.DeferredSignIn.StashSignOut(Arg.Any<string>()).Returns(StashedSignOutKey);

		var probe = await harness.RunAsync(manager => manager.ForgetTwoFactorClientAsync(), responseAlreadyStarted: true);

		probe.Exception.ShouldBeNull();
		probe.RememberKey.ShouldBe(StashedSignOutKey);
		probe.IdentityKey.ShouldBeNull();
		harness.DeferredSignIn.Received(1).StashSignOut(_rememberMeScheme);
		harness.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignIn(default!, default!, default!);
	}

	[Fact]
	async Task Refresh_sign_in_reaches_the_identity_stash_once_the_response_has_started()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		harness.DeferredSignIn
			.StashSignIn(Arg.Any<string>(), Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>())
			.Returns(StashedSignInKey);
		var signedIn = await harness.RunAsync(manager =>
			manager.SignInWithClaimsAsync(harness.User, isPersistent: false, additionalClaims: []));
		var cookie = TwoFactorHarness.CookieOf(signedIn.SetCookieFor(".AspNetCore.Identity.Application")!);

		var probe = await harness.RunAsync(manager => manager.RefreshSignInAsync(harness.User),
			responseAlreadyStarted: true, cookie);

		probe.Exception.ShouldBeNull();
		probe.IdentityKey.ShouldBe(StashedSignInKey);
		harness.DeferredSignIn.Received(1)
			.StashSignIn(_scheme, Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>());
	}

	// 1. The stash completes through Midgard's real /_auth/complete endpoint and the cookie it writes is honored.
	// 2. A rotated stamp is still honored inside SecurityStampValidatorOptions.ValidationInterval -- the validator
	//    does not run and the cookie is accepted on its name claim alone.
	// 3. Past the interval the real TwoFactorSecurityStampValidator runs, and only a rotated stamp is rejected.
	// With responseAlreadyStarted, requests 2-4 run on a circuit, where the manager reads the cookie itself.
	static async Task<TwoFactorHarness.Probe<bool>> RunRememberedClientScenarioAsync(bool rotateStamp,
		bool responseAlreadyStarted = false)
	{
		using var harness = await TwoFactorHarness.StartAsync(realDeferredSignIn: true);
		var stashed = await harness.RunAsync(manager => manager.RememberTwoFactorClientAsync(harness.User),
			responseAlreadyStarted: true);
		var completion = harness.DeferredSignIn.BuildCompletionUrl(stashed.RememberKey!, "/");
		var setCookies = await harness.GetSetCookiesAsync(completion);
		var cookie = TwoFactorHarness.CookieOf(setCookies.Single(header =>
			header.StartsWith($"{_rememberMeScheme}=", StringComparison.Ordinal)));
		Func<NorseSignInManager, Task<bool>> remembered = manager => manager.IsTwoFactorClientRememberedAsync(harness.User);

		(await harness.RunAsync(remembered, responseAlreadyStarted, cookie)).Value.ShouldBeTrue();
		if (rotateStamp)
			harness.Stamp = Guid.NewGuid().ToString();
		(await harness.RunAsync(remembered, responseAlreadyStarted, cookie)).Value.ShouldBeTrue();

		harness.Clock.Advance(TwoFactorHarness.ValidationInterval + TimeSpan.FromMinutes(1));
		return await harness.RunAsync(remembered, responseAlreadyStarted, cookie);
	}

	static Func<NorseSignInManager, Task<SignInResult>> PasswordSignInAsync(TwoFactorHarness harness,
		bool isPersistent = false) =>
		manager => manager.PasswordSignInAsync(harness.User, TwoFactorHarness.Password, isPersistent,
			lockoutOnFailure: false);

	static IdentityResult LockoutResetFailure(string resultKind) =>
		IdentityResult.Failed(resultKind == "Failed" ?
			new IdentityErrorDescriber().DefaultError() :
			new IdentityError
			{
				Code = NorseIdentityErrorCodes.IndeterminateOutcome,
				Description = "The commit outcome is unknown."
			});

	static async Task<Probe> RunAsync(bool useNorseSignInManager, bool responseAlreadyStarted, bool signOut)
	{
		var deferredSignIn = Substitute.For<IDeferredSignIn>();
		deferredSignIn.StashSignIn(Arg.Any<string>(), Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>())
			.Returns(StashedSignInKey);
		deferredSignIn.StashSignOut(Arg.Any<string>()).Returns(StashedSignOutKey);

		Exception? caught = null;
		string? itemsKey = null;
		var setCookiePresent = false;

		using var host = await new HostBuilder()
			.ConfigureWebHost(webHost => webHost
				.UseTestServer()
				.ConfigureServices(services => services.AddAuthentication(_scheme).AddCookie(_scheme))
				.Configure(app => app.Run(async context =>
				{
					if (responseAlreadyStarted)
						await context.Response.WriteAsync(" ");

					NorseUser user = new() { UserName = "user@example.com", Email = "user@example.com" };
					var claimsFactory = Substitute.For<IUserClaimsPrincipalFactory<NorseUser>>();
					claimsFactory.CreateAsync(Arg.Any<NorseUser>())
						.Returns(new ClaimsPrincipal(new ClaimsIdentity(_scheme)));

					var userManager = Substitute.For<UserManager<NorseUser>>(
						Substitute.For<IUserStore<NorseUser>>(), null!, new PasswordHasher<NorseUser>(),
						Array.Empty<IUserValidator<NorseUser>>(), Array.Empty<IPasswordValidator<NorseUser>>(),
						new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null!,
						NullLogger<UserManager<NorseUser>>.Instance);

					HttpContextAccessor accessor = new() { HttpContext = context };
					var schemes = Substitute.For<IAuthenticationSchemeProvider>();
					var confirmation = Substitute.For<IUserConfirmation<NorseUser>>();

					SignInManager<NorseUser> signInManager = useNorseSignInManager ?
						new NorseSignInManager(
							userManager, accessor, claimsFactory, Options.Create(new IdentityOptions()),
							NullLogger<SignInManager<NorseUser>>.Instance, schemes, confirmation, deferredSignIn,
							context.RequestServices.GetRequiredService<IDataProtectionProvider>()) :
						new SignInManager<NorseUser>(
							userManager, accessor, claimsFactory, Options.Create(new IdentityOptions()),
							NullLogger<SignInManager<NorseUser>>.Instance, schemes, confirmation);

					try
					{
						if (signOut)
							await signInManager.SignOutAsync();
						else
							await signInManager.SignInWithClaimsAsync(user, isPersistent: false, additionalClaims: []);
					}
					catch (Exception ex)
					{
						caught = ex;
					}

					itemsKey = context.Items.TryGetValue(NorseSignInManager.DeferredSignInKeyItemName, out var value) ?
						value as string :
						null;
					setCookiePresent = context.Response.Headers.ContainsKey("Set-Cookie");
				})))
			.StartAsync();

		using var client = host.GetTestServer().CreateClient();
		await client.GetAsync(new Uri("/", UriKind.Relative));

		return new Probe(caught, deferredSignIn, itemsKey, setCookiePresent);
	}

	// SignInOrTwoFactorAsync itself is protected, so the stock manager is driven through PasswordSignInAsync,
	// the real public entry point LoginHandler itself calls.
	static async Task<Probe> RunUnmodifiedTwoFactorAsync()
	{
		Exception? caught = null;

		using var host = await new HostBuilder()
			.ConfigureWebHost(webHost => webHost
				.UseTestServer()
				.ConfigureServices(services => services
					.AddAuthentication(_scheme)
					.AddCookie(_scheme)
					.AddCookie(IdentityConstants.TwoFactorUserIdScheme))
				.Configure(app => app.Run(async context =>
				{
					await context.Response.WriteAsync(" ");

					NorseUser user = new() { UserName = "user@example.com", Email = "user@example.com" };
					var claimsFactory = Substitute.For<IUserClaimsPrincipalFactory<NorseUser>>();

					// CanSignInAsync/IsLockedOut both pass unstubbed (IdentityOptions defaults to no
					// confirmation requirements; SupportsUserLockout defaults false on an unstubbed
					// substitute) -- CheckPasswordAsync true is the only thing CheckPasswordSignInAsync
					// needs to report Success, then PasswordSignInAsync calls SignInOrTwoFactorAsync,
					// which re-checks 2FA itself via the three stubs below.
					var userManager = Substitute.For<UserManager<NorseUser>>(
						Substitute.For<IUserStore<NorseUser>>(), null!, new PasswordHasher<NorseUser>(),
						Array.Empty<IUserValidator<NorseUser>>(), Array.Empty<IPasswordValidator<NorseUser>>(),
						new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null!,
						NullLogger<UserManager<NorseUser>>.Instance);
					userManager.CheckPasswordAsync(user, "correct-horse").Returns(true);
					userManager.SupportsUserTwoFactor.Returns(true);
					userManager.GetTwoFactorEnabledAsync(user).Returns(true);
					userManager.GetValidTwoFactorProvidersAsync(user).Returns((IList<string>)["Authenticator"]);
					userManager.GetUserIdAsync(user).Returns(user.Id.ToString());

					HttpContextAccessor accessor = new() { HttpContext = context };
					// IsTwoFactorClientRememberedAsync checks TwoFactorRememberMeScheme, left unstubbed (null) on
					// purpose -- "not remembered", forcing the genuinely-requires-2FA branch. TwoFactorUserIdScheme
					// is the one the stock SignInOrTwoFactorAsync checks before writing the partial cookie.
					var schemes = Substitute.For<IAuthenticationSchemeProvider>();
					schemes.GetSchemeAsync(IdentityConstants.TwoFactorUserIdScheme)
						.Returns(new AuthenticationScheme(IdentityConstants.TwoFactorUserIdScheme, null,
							typeof(CookieAuthenticationHandler)));

					SignInManager<NorseUser> signInManager = new(
						userManager, accessor, claimsFactory, Options.Create(new IdentityOptions()),
						NullLogger<SignInManager<NorseUser>>.Instance, schemes,
						Substitute.For<IUserConfirmation<NorseUser>>());

					try
					{
						await signInManager.PasswordSignInAsync(
							user, "correct-horse", isPersistent: false, lockoutOnFailure: false);
					}
					catch (Exception ex)
					{
						caught = ex;
					}
				})))
			.StartAsync();

		using var client = host.GetTestServer().CreateClient();
		await client.GetAsync(new Uri("/", UriKind.Relative));

		return new Probe(caught, Substitute.For<IDeferredSignIn>(), null, false);
	}

	sealed record Probe(
		Exception? Exception,
		IDeferredSignIn DeferredSignIn,
		string? ItemsKey,
		bool SetCookieHeaderPresent);
}
