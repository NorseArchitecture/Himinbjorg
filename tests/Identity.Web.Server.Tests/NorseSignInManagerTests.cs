using System.Security.Claims;
using System.Text;
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
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Tests.Passkeys;

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
	const string CreationOptionsJson = "{\"challenge\":\"creation\"}";
	const string RawAttestationState = "{\"challenge\":\"raw-attestation-state\"}";
	const string CredentialJson = "{\"id\":\"credential\"}";
	const string RequestOptionsJson = "{\"challenge\":\"request\"}";
	const string RawAssertionState = "{\"challenge\":\"raw-assertion-state\",\"userId\":null}";

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

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
			TwoFactorHarness.ExternalProvider, ReturnUrl: "/"));
		TwoFactorChallenge.TryUnprotect(harness.ChallengeProtector, password.Token!, out var passwordChallenge)
			.ShouldBeTrue();
		passwordChallenge.ShouldBe(new(harness.UserId, harness.Stamp, IsPersistent: false, LoginProvider: null,
			ReturnUrl: "/"));
	}

	// T3-18 (Buvy): external login requires the second factor, by construction rather than by every caller's choice.
	[Fact]
	async Task An_external_sign_in_that_asks_to_bypass_two_factor_throws()
	{
		using var harness = await TwoFactorHarness.StartAsync();

		var probe = await harness.RunAsync(manager => manager.ExternalLoginSignInAsync(
			TwoFactorHarness.ExternalProvider, TwoFactorHarness.ExternalProviderKey, isPersistent: false,
			bypassTwoFactor: true));

		probe.Exception.ShouldBeOfType<InvalidOperationException>();
		probe.Token.ShouldBeNull();
		probe.SetCookieHeaderPresent.ShouldBeFalse();
		await harness.UserManager.DidNotReceiveWithAnyArgs().FindByLoginAsync(default!, default!);
	}

	// The base three-argument overload (decompiled RC3, 2026-10-28) forwards to the four-argument one with
	// bypassTwoFactor: false, so it stays legal and still asks for the challenge.
	[Fact]
	async Task The_three_argument_external_sign_in_still_requires_the_challenge()
	{
		using var harness = await TwoFactorHarness.StartAsync();

		var probe = await harness.RunAsync(manager => manager.ExternalLoginSignInAsync(
			TwoFactorHarness.ExternalProvider, TwoFactorHarness.ExternalProviderKey, isPersistent: false));

		probe.Exception.ShouldBeNull();
		probe.Value.ShouldBe(SignInResult.TwoFactorRequired);
		probe.Token.ShouldNotBeNull();
	}

	// The mint takes the parked landing into the token and removes the item; the completion answers it.
	[Fact]
	async Task A_local_return_url_survives_the_two_factor_challenge()
	{
		const string Landing = "/Account/Manage?x=1";
		using var harness = await TwoFactorHarness.StartAsync();
		bool? leftParked = null;

		var minted = await harness.RunAsync(async manager =>
		{
			using (ParkedReturnUrl.Park(manager.Context, Landing))
			{
				var result = await PasswordSignInAsync(harness)(manager);
				leftParked = manager.Context.Items.ContainsKey(NorseSignInManager.ReturnUrlItemName);
				return result;
			}
		});
		var completed = await harness.RunAsync(manager =>
			manager.TwoFactorChallengeSignInAsync(minted.Token!, TwoFactorHarness.AuthenticatorCode,
				rememberClient: false));

		leftParked.ShouldBe(false);
		TwoFactorChallenge.TryUnprotect(harness.ChallengeProtector, minted.Token!, out var challenge).ShouldBeTrue();
		challenge.ReturnUrl.ShouldBe(Landing);
		completed.Value.ShouldBe(new(SignInResult.Success, Landing));
	}

	[Fact]
	async Task A_mint_without_a_parked_url_lands_on_the_app_root()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = (await harness.RunAsync(PasswordSignInAsync(harness))).Token!;

		var authenticator = await harness.RunAsync(manager =>
			manager.TwoFactorChallengeSignInAsync(token, TwoFactorHarness.AuthenticatorCode, rememberClient: false));
		var recovery = await harness.RunAsync(manager =>
			manager.RecoveryCodeChallengeSignInAsync(token, TwoFactorHarness.RecoveryCode));

		TwoFactorChallenge.TryUnprotect(harness.ChallengeProtector, token, out var challenge).ShouldBeTrue();
		challenge.ReturnUrl.ShouldBe("/");
		authenticator.Value.ShouldBe(new(SignInResult.Success, "/"));
		recovery.Value.ShouldBe(new(SignInResult.Success, "/"));
	}

	[Fact]
	async Task A_correct_authenticator_code_completes_the_sign_in_with_amr_mfa()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = (await harness.RunAsync(PasswordSignInAsync(harness, isPersistent: true))).Token!;

		var probe = await harness.RunAsync(manager =>
			manager.TwoFactorChallengeSignInAsync(token, TwoFactorHarness.AuthenticatorCode, rememberClient: false));

		probe.Exception.ShouldBeNull();
		probe.Value.ShouldNotBeNull().Result.ShouldBe(SignInResult.Success);
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

		probe.Value.ShouldNotBeNull().Result.ShouldBe(SignInResult.Success);
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

		probe.Value.ShouldNotBeNull().Result.ShouldBe(SignInResult.Success);
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
		probe.Value.ShouldNotBeNull().Result.ShouldBe(SignInResult.Failed);
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
		probe.Value.ShouldNotBeNull().Result.ShouldBe(SignInResult.Failed);
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

		probe.Value.ShouldNotBeNull().Result.ShouldBe(SignInResult.LockedOut);
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

		probe.Value.ShouldNotBeNull().Result.ShouldBe(SignInResult.Failed);
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

		probe.Value.ShouldNotBeNull().Result.ShouldBe(SignInResult.Failed);
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

		wrong.Value.ShouldNotBeNull().Result.ShouldBe(SignInResult.Failed);
		wrong.SetCookieHeaderPresent.ShouldBeFalse();
		await harness.UserManager.DidNotReceiveWithAnyArgs().AccessFailedAsync(default!);
		right.Value.ShouldNotBeNull().Result.ShouldBe(SignInResult.Success);
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
		authenticator.Value.ShouldNotBeNull().Result.ShouldBe(SignInResult.Failed);
		recovery.Exception.ShouldBeNull();
		recovery.Value.ShouldNotBeNull().Result.ShouldBe(SignInResult.Failed);
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

		authenticator.Value.ShouldNotBeNull().Result.ShouldBe(SignInResult.Success);
		await harness.UserManager.Received(1).VerifyTwoFactorTokenAsync(harness.User,
			TokenOptions.DefaultAuthenticatorProvider, TwoFactorHarness.AuthenticatorCode);
		recovery.Value.ShouldNotBeNull().Result.ShouldBe(SignInResult.Success);
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

	[Fact]
	async Task Creation_options_protect_the_attestation_state()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		ArrangeCreationOptions(harness);
		var before = DateTimeOffset.UtcNow;

		var probe = await harness.RunAsync(manager => manager.CreatePasskeyOptionsAsync(harness.User, Cancellation));

		var ceremony = probe.Value.ShouldNotBeNull();
		ceremony.OptionsJson.ShouldBe(CreationOptionsJson);
		ceremony.State.ShouldNotContain(RawAttestationState);
		harness.AttestationProtector.Unprotect(ceremony.State, out var expiration).ShouldBe(RawAttestationState);
		var timeout = new IdentityPasskeyOptions().AuthenticatorTimeout;
		expiration.ShouldBeInRange(before + timeout - TimeSpan.FromSeconds(5), DateTimeOffset.UtcNow + timeout);
		await harness.PasskeyHandler.Received(1).MakeCreationOptionsAsync(
			Arg.Is<PasskeyUserEntity>(entity =>
				entity.Id == harness.UserId && entity.Name == harness.User.UserName
				&& entity.DisplayName == harness.User.UserName),
			Arg.Any<HttpContext>());
	}

	[Fact]
	async Task Attestation_unprotects_the_state_before_the_handler_sees_it()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		ArrangeCreationOptions(harness);
		var verified = PasskeyAttestationResult.Fail(new PasskeyException("the handler's own answer"));
		harness.PasskeyHandler.PerformAttestationAsync(Arg.Any<PasskeyAttestationContext>()).Returns(verified);
		var ceremony = (await harness.RunAsync(manager => manager.CreatePasskeyOptionsAsync(harness.User, Cancellation)))
			.Value.ShouldNotBeNull();

		var probe = await harness.RunAsync(manager =>
			manager.AttestPasskeyAsync(CredentialJson, ceremony.State, Cancellation));

		probe.Value.ShouldBeSameAs(verified);
		await harness.PasskeyHandler.Received(1).PerformAttestationAsync(Arg.Is<PasskeyAttestationContext>(context =>
			context.AttestationState == RawAttestationState && context.CredentialJson == CredentialJson
			&& context.HttpContext != null));
	}

	[Fact]
	async Task A_tampered_state_fails_attestation_without_calling_the_handler()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var state = harness.AttestationProtector.Protect(RawAttestationState, TimeSpan.FromMinutes(5));
		var tampered = string.Concat(state.AsSpan(0, state.Length - 2), state[^2] == 'A' ? "BA" : "AA");

		await ShouldFailAttestationAsync(harness, tampered);
		await ShouldFailAttestationAsync(harness, "not a protected state");
	}

	[Fact]
	async Task An_expired_state_fails_attestation()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var expired = harness.AttestationProtector.Protect(RawAttestationState, DateTimeOffset.UtcNow.AddSeconds(-1));

		await ShouldFailAttestationAsync(harness, expired);
	}

	[Fact]
	async Task A_state_from_another_purpose_fails_attestation()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var challenge = harness.ChallengeProtector.Protect(RawAttestationState, TimeSpan.FromMinutes(5));

		await ShouldFailAttestationAsync(harness, challenge);
	}

	static async Task ShouldFailAttestationAsync(TwoFactorHarness harness, string state)
	{
		var probe = await harness.RunAsync(manager => manager.AttestPasskeyAsync(CredentialJson, state, Cancellation));

		probe.Exception.ShouldBeNull();
		var result = probe.Value.ShouldNotBeNull();
		result.Succeeded.ShouldBeFalse();
		result.Failure!.Message.ShouldBe("The passkey could not be verified. Try again.");
		await harness.PasskeyHandler.DidNotReceiveWithAnyArgs().PerformAttestationAsync(default!);
	}

	static void ArrangeCreationOptions(TwoFactorHarness harness) =>
		harness.PasskeyHandler.MakeCreationOptionsAsync(Arg.Any<PasskeyUserEntity>(), Arg.Any<HttpContext>())
			.Returns(new PasskeyCreationOptionsResult
			{
				CreationOptionsJson = CreationOptionsJson,
				AttestationState = RawAttestationState
			});

	[Fact]
	async Task Request_options_protect_the_assertion_state()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		ArrangeRequestOptions(harness);
		var before = DateTimeOffset.UtcNow;

		var probe = await harness.RunAsync(manager => manager.CreatePasskeyRequestOptionsAsync(Cancellation));

		var ceremony = probe.Value.ShouldNotBeNull();
		ceremony.OptionsJson.ShouldBe(RequestOptionsJson);
		ceremony.State.ShouldNotContain(RawAssertionState);
		harness.AssertionProtector.Unprotect(ceremony.State, out var expiration).ShouldBe(RawAssertionState);
		var timeout = new IdentityPasskeyOptions().AuthenticatorTimeout;
		expiration.ShouldBeInRange(before + timeout - TimeSpan.FromSeconds(5), DateTimeOffset.UtcNow + timeout);
		await harness.PasskeyHandler.Received(1).MakeRequestOptionsAsync(null, Arg.Any<HttpContext>());
		harness.Ledger.Requests.ShouldBeEmpty("starting a ceremony consumes nothing");
	}

	[Fact]
	async Task A_tampered_assertion_state_fails_without_calling_the_handler()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var state = harness.AssertionProtector.Protect(RawAssertionState, TimeSpan.FromMinutes(5));
		var tampered = string.Concat(state.AsSpan(0, state.Length - 2), state[^2] == 'A' ? "BA" : "AA");

		await ShouldFailAssertionAsync(harness, tampered);
		await ShouldFailAssertionAsync(harness, "not a protected state");
		await ShouldFailAssertionAsync(harness,
			harness.AssertionProtector.Protect(RawAssertionState, DateTimeOffset.UtcNow.AddSeconds(-1)));
	}

	[Fact]
	async Task An_attestation_state_cannot_complete_an_assertion()
	{
		using var harness = await TwoFactorHarness.StartAsync();

		await ShouldFailAssertionAsync(harness,
			harness.AttestationProtector.Protect(RawAssertionState, TimeSpan.FromMinutes(5)));
	}

	[Fact]
	async Task A_successful_assertion_signs_in_and_updates_the_sign_count()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var passkey = ArrangeAssertion(harness, signCount: 7);
		var state = await RequestStateAsync(harness);

		var probe = await harness.RunAsync(AssertAsync(state));

		probe.Exception.ShouldBeNull();
		probe.Value.ShouldNotBeNull().Succeeded.ShouldBeTrue();
		probe.SetCookieFor(".AspNetCore.Identity.Application").ShouldNotBeNull();
		await harness.UserManager.Received(1).AddOrUpdatePasskeyAsync(harness.User,
			Arg.Is<UserPasskeyInfo>(p => ReferenceEquals(p, passkey) && p.SignCount == 7));
		await harness.PasskeyHandler.Received(1).PerformAssertionAsync(Arg.Is<PasskeyAssertionContext>(context =>
			context.AssertionState == RawAssertionState && context.CredentialJson == CredentialJson
			&& context.HttpContext != null));
		var consumed = harness.Ledger.Requests.ShouldHaveSingleItem();
		consumed.State.ShouldBe(Encoding.UTF8.GetBytes(RawAssertionState),
			"the ledger is handed the unprotected state's UTF-8 bytes (P5)");
		consumed.ExpiresAt.ShouldBeInRange(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow + new IdentityPasskeyOptions().AuthenticatorTimeout);
	}

	[Fact]
	async Task A_replayed_assertion_signs_in_nothing()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		ArrangeAssertion(harness, signCount: 1);
		var state = await RequestStateAsync(harness);

		var first = await harness.RunAsync(AssertAsync(state));
		var replay = await harness.RunAsync(AssertAsync(state));

		first.Value.ShouldNotBeNull().Succeeded.ShouldBeTrue();
		replay.Exception.ShouldBeNull();
		replay.Value.ShouldNotBeNull().ShouldBe(SignInResult.Failed);
		replay.SetCookieHeaderPresent.ShouldBeFalse();
		await harness.PasskeyHandler.Received(1).PerformAssertionAsync(Arg.Any<PasskeyAssertionContext>());
		await harness.UserManager.Received(1).AddOrUpdatePasskeyAsync(harness.User, Arg.Any<UserPasskeyInfo>());
	}

	// A store fault inside the handler folds into a failed ceremony: the answer stays the fixed refusal, and the cause
	// is logged with its exception at Information or above, so an outage never reads as "the passkey could not be
	// used" with nothing in the logs.
	[Fact]
	async Task A_failed_assertion_logs_its_exception()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		PasskeyException failure = new("The store faulted.", new InvalidOperationException("database down"));
		harness.PasskeyHandler.PerformAssertionAsync(Arg.Any<PasskeyAssertionContext>())
			.Returns(PasskeyAssertionResult.Fail<NorseUser>(failure));
		var state = await RequestStateAsync(harness);

		(await harness.RunAsync(AssertAsync(state))).Value.ShouldBe(SignInResult.Failed);

		ShouldHaveLogged(harness, failure);
	}

	[Fact]
	async Task A_failed_attestation_logs_its_exception()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		ArrangeCreationOptions(harness);
		PasskeyException failure = new("The store faulted.", new InvalidOperationException("database down"));
		harness.PasskeyHandler.PerformAttestationAsync(Arg.Any<PasskeyAttestationContext>())
			.Returns(PasskeyAttestationResult.Fail(failure));
		var ceremony = (await harness.RunAsync(manager => manager.CreatePasskeyOptionsAsync(harness.User, Cancellation)))
			.Value.ShouldNotBeNull();

		(await harness.RunAsync(manager => manager.AttestPasskeyAsync(CredentialJson, ceremony.State, Cancellation)))
			.Value.ShouldNotBeNull().Succeeded.ShouldBeFalse();

		ShouldHaveLogged(harness, failure);
	}

	static void ShouldHaveLogged(TwoFactorHarness harness, PasskeyException failure)
	{
		var logged = harness.Logs.GetSnapshot().Where(record => ReferenceEquals(record.Exception, failure)).ShouldHaveSingleItem();
		((int)logged.Level).ShouldBeGreaterThanOrEqualTo((int)LogLevel.Information);
	}

	[Fact]
	async Task A_failed_first_assertion_still_burns_its_challenge()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		harness.PasskeyHandler.PerformAssertionAsync(Arg.Any<PasskeyAssertionContext>())
			.Returns(PasskeyAssertionResult.Fail<NorseUser>(new PasskeyException("The assertion signature is invalid.")),
				PasskeyAssertionResult.Success(TestPasskeys.Info([0x0B]), harness.User));
		var state = await RequestStateAsync(harness);

		var first = await harness.RunAsync(AssertAsync(state));
		var retry = await harness.RunAsync(AssertAsync(state));

		first.Value.ShouldBe(SignInResult.Failed);
		retry.Value.ShouldBe(SignInResult.Failed);
		retry.SetCookieHeaderPresent.ShouldBeFalse();
		await harness.PasskeyHandler.Received(1).PerformAssertionAsync(Arg.Any<PasskeyAssertionContext>());
		await harness.UserManager.DidNotReceiveWithAnyArgs().AddOrUpdatePasskeyAsync(default!, default!);
	}

	[Fact]
	async Task A_failed_sign_count_update_signs_in_nothing()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		ArrangeAssertion(harness, signCount: 2);
		harness.UserManager.AddOrUpdatePasskeyAsync(harness.User, Arg.Any<UserPasskeyInfo>())
			.Returns(IdentityResult.Failed(new IdentityError
			{
				Code = NorseIdentityErrorCodes.IndeterminateOutcome,
				Description = "The commit outcome is unknown."
			}));
		var state = await RequestStateAsync(harness);

		var probe = await harness.RunAsync(AssertAsync(state));

		probe.Value.ShouldBe(SignInResult.Failed);
		probe.SetCookieHeaderPresent.ShouldBeFalse();
	}

	[Fact]
	async Task A_locked_out_user_cannot_sign_in_with_a_passkey()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		ArrangeAssertion(harness, signCount: 3);
		harness.UserManager.IsLockedOutAsync(harness.User).Returns(true);
		var state = await RequestStateAsync(harness);

		var probe = await harness.RunAsync(AssertAsync(state));

		probe.Value.ShouldNotBeNull().IsLockedOut.ShouldBeTrue();
		probe.SetCookieHeaderPresent.ShouldBeFalse();
		await harness.UserManager.DidNotReceiveWithAnyArgs().AddOrUpdatePasskeyAsync(default!, default!);
	}

	// The recorded base value (decompiled RC3, task 4.6 F6) is bypassTwoFactor: true, ruled binding: a user-verified
	// passkey is itself a multi-factor credential. The harness user has two-factor enabled and no remembered client.
	[Fact]
	async Task A_two_factor_account_follows_the_recorded_bypass()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		ArrangeAssertion(harness, signCount: 4);
		(await harness.UserManager.GetTwoFactorEnabledAsync(harness.User)).ShouldBeTrue();
		var state = await RequestStateAsync(harness);

		var probe = await harness.RunAsync(AssertAsync(state));

		probe.Value.ShouldNotBeNull().Succeeded.ShouldBeTrue();
		probe.Token.ShouldBeNull("no two-factor challenge is minted");
		probe.SetCookieFor(".AspNetCore.Identity.Application").ShouldNotBeNull();
	}

	[Fact]
	async Task Request_options_require_user_verification()
	{
		ServiceCollection services = new();
		using var certificate = IdentityTestCertificate.CreateFresh();
		services.AddNorseIdentity(certificate);
		using var provider = services.BuildServiceProvider();
		var passkeyOptions = provider.GetRequiredService<IOptions<IdentityPasskeyOptions>>();
		using var userManager = MockUserManager.Create();
		DefaultHttpContext context = new();
		context.Request.Host = new HostString("example.test");
		NorseSignInManager manager = new(
			userManager, new HttpContextAccessor { HttpContext = context },
			Substitute.For<IUserClaimsPrincipalFactory<NorseUser>>(), Options.Create(new IdentityOptions()),
			NullLogger<SignInManager<NorseUser>>.Instance, Substitute.For<IAuthenticationSchemeProvider>(),
			Substitute.For<IUserConfirmation<NorseUser>>(), Substitute.For<IDeferredSignIn>(),
			new EphemeralDataProtectionProvider(), new PasskeyHandler<NorseUser>(userManager, passkeyOptions),
			passkeyOptions, new InMemoryPasskeyChallengeLedger());

		var ceremony = await manager.CreatePasskeyRequestOptionsAsync(Cancellation);

		ceremony.OptionsJson.ShouldContain("\"userVerification\":\"required\"");
	}

	static async Task ShouldFailAssertionAsync(TwoFactorHarness harness, string state)
	{
		var probe = await harness.RunAsync(AssertAsync(state));

		probe.Exception.ShouldBeNull();
		probe.Value.ShouldBe(SignInResult.Failed);
		probe.SetCookieHeaderPresent.ShouldBeFalse();
		await harness.PasskeyHandler.DidNotReceiveWithAnyArgs().PerformAssertionAsync(default!);
		harness.Ledger.Requests.ShouldBeEmpty("a state that never unprotects is never consumed");
	}

	static Func<NorseSignInManager, Task<SignInResult>> AssertAsync(string state) =>
		manager => manager.PasskeyAssertionSignInAsync(CredentialJson, state, isPersistent: false, Cancellation);

	static void ArrangeRequestOptions(TwoFactorHarness harness) =>
		harness.PasskeyHandler.MakeRequestOptionsAsync(Arg.Any<NorseUser?>(), Arg.Any<HttpContext>())
			.Returns(new PasskeyRequestOptionsResult
			{
				RequestOptionsJson = RequestOptionsJson,
				AssertionState = RawAssertionState
			});

	// What the real handler hands back on success: the stored passkey with the authenticator's new sign count set.
	static UserPasskeyInfo ArrangeAssertion(TwoFactorHarness harness, uint signCount)
	{
		var passkey = TestPasskeys.Info([0x0A]);
		passkey.SignCount = signCount;
		harness.PasskeyHandler.PerformAssertionAsync(Arg.Any<PasskeyAssertionContext>())
			.Returns(PasskeyAssertionResult.Success(passkey, harness.User));
		return passkey;
	}

	static async Task<string> RequestStateAsync(TwoFactorHarness harness)
	{
		ArrangeRequestOptions(harness);
		return (await harness.RunAsync(manager => manager.CreatePasskeyRequestOptionsAsync(Cancellation)))
			.Value.ShouldNotBeNull().State;
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
							context.RequestServices.GetRequiredService<IDataProtectionProvider>(),
							Substitute.For<IPasskeyHandler<NorseUser>>(), Options.Create(new IdentityPasskeyOptions()),
							new InMemoryPasskeyChallengeLedger()) :
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
