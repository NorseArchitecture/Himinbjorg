using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Tests.Passkeys;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     <c>signInManager.Outcome</c> (2026-10-24 explicit-writes spec §4.12): the password path against a substituted
///     manager, the challenge paths against a real <see cref="NorseSignInManager" /> on <see cref="TwoFactorHarness" />.
/// </summary>
public sealed class SignInManagerOutcomeViewTests
{
	readonly SignInManager<NorseUser> _signInManager = MockSignInManager.Create();

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task SignInResult_states_map_to_LockedOut_NotAllowed_InvalidCredentials()
	{
		Answer("locked", SignInResult.LockedOut);
		Answer("refused", SignInResult.NotAllowed);
		Answer("wrong", SignInResult.Failed);
		Answer("right", SignInResult.Success);
		Answer("second-factor", SignInResult.TwoFactorRequired);

		(await Category("locked")).ShouldBe(ErrorCategory.LockedOut);
		(await Category("refused")).ShouldBe(ErrorCategory.NotAllowed);
		(await Category("wrong")).ShouldBe(ErrorCategory.InvalidCredentials);
		(await Completion("right")).ShouldBe(SignInCompletion.SignedIn);
		(await Completion("second-factor")).ShouldBe(SignInCompletion.RequiresTwoFactor);
	}

	[Fact]
	async Task An_indeterminate_increment_and_a_destroyed_key_are_outcomes_not_exceptions()
	{
		_signInManager.PasswordSignInAsync("indeterminate", "pw", false, true)
			.ThrowsAsync(new IndeterminateWriteException("the increment", new TimeoutException()));
		_signInManager.PasswordSignInAsync("erased", "pw", false, true)
			.ThrowsAsync(new KeyDestroyedException(new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch)));

		(await Category("indeterminate")).ShouldBe(ErrorCategory.Indeterminate);
		(await Category("erased")).ShouldBe(ErrorCategory.Erased);
	}

	[Fact]
	async Task Challenge_sign_in_states_map_like_password_sign_in_and_success_answers_the_landing()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = await ParkChallengeAsync(harness);
		harness.UserManager.RedeemTwoFactorRecoveryCodeAsync(harness.User, "wrong-code")
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().RecoveryCodeRedemptionFailed()));

		var wrongCode = await ChallengeAsync(harness, token, "000000");
		var wrongRecoveryCode = await RecoveryAsync(harness, token, "wrong-code");
		var rightCode = await ChallengeAsync(harness, token, TwoFactorHarness.AuthenticatorCode);
		var rightRecoveryCode = await RecoveryAsync(harness, token, TwoFactorHarness.RecoveryCode);
		var lockedOut = false;
		harness.UserManager.AccessFailedAsync(harness.User).Returns(_ =>
		{
			lockedOut = true;
			return IdentityResult.Success;
		});
		harness.UserManager.IsLockedOutAsync(harness.User).Returns(_ => lockedOut);
		var trippedLockout = await ChallengeAsync(harness, token, "000000");

		CategoryOf(wrongCode).ShouldBe(ErrorCategory.InvalidCredentials);
		CategoryOf(wrongRecoveryCode).ShouldBe(ErrorCategory.InvalidCredentials);
		LandingOf(rightCode).ShouldBe("/");
		LandingOf(rightRecoveryCode).ShouldBe("/");
		CategoryOf(trippedLockout).ShouldBe(ErrorCategory.LockedOut);
	}

	[Fact]
	async Task A_stock_manager_fails_loud_on_the_challenge_methods()
	{
		await Should.ThrowAsync<InvalidOperationException>(async () =>
			await _signInManager.Outcome.TwoFactorChallengeSignInAsync("tok", "123456", false, Cancellation));
		await Should.ThrowAsync<InvalidOperationException>(async () =>
			await _signInManager.Outcome.RecoveryCodeChallengeSignInAsync("tok", "abcde-fghij", Cancellation));
	}

	[Fact]
	async Task An_erased_user_answers_Erased()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = await ParkChallengeAsync(harness);
		harness.UserManager.FindByIdAsync(harness.UserId)
			.ThrowsAsync(new KeyDestroyedException(new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch)));

		var code = await ChallengeAsync(harness, token, TwoFactorHarness.AuthenticatorCode);
		var recoveryCode = await RecoveryAsync(harness, token, TwoFactorHarness.RecoveryCode);

		CategoryOf(code).ShouldBe(ErrorCategory.Erased);
		CategoryOf(recoveryCode).ShouldBe(ErrorCategory.Erased);
	}

	[Fact]
	async Task External_sign_in_states_map_like_password_sign_in()
	{
		AnswerExternal("signed-in", SignInResult.Success);
		AnswerExternal("second-factor", SignInResult.TwoFactorRequired);
		AnswerExternal("unknown", SignInResult.Failed);

		CompletionOf(await ExternalAsync("signed-in")).ShouldBe(SignInCompletion.SignedIn);
		CompletionOf(await ExternalAsync("second-factor")).ShouldBe(SignInCompletion.RequiresTwoFactor);
		CategoryOf(await ExternalAsync("unknown")).ShouldBe(ErrorCategory.InvalidCredentials);
	}

	[Fact]
	async Task It_never_bypasses_two_factor()
	{
		AnswerExternal("key", SignInResult.TwoFactorRequired);

		await _signInManager.Outcome.ExternalLoginSignInAsync("Provider", "key", false, Cancellation);

		await _signInManager.Received(1).ExternalLoginSignInAsync("Provider", "key", false, false);
		await _signInManager.DidNotReceive().ExternalLoginSignInAsync(Arg.Any<string>(), Arg.Any<string>(),
			Arg.Any<bool>(), true);
	}

	[Fact]
	async Task An_indeterminate_or_erased_external_sign_in_is_an_outcome_not_an_exception()
	{
		_signInManager.ExternalLoginSignInAsync("Provider", "indeterminate", false, false)
			.ThrowsAsync(new IndeterminateWriteException("the sign-in", new TimeoutException()));
		_signInManager.ExternalLoginSignInAsync("Provider", "erased", false, false)
			.ThrowsAsync(new KeyDestroyedException(new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch)));

		CategoryOf(await ExternalAsync("indeterminate")).ShouldBe(ErrorCategory.Indeterminate);
		CategoryOf(await ExternalAsync("erased")).ShouldBe(ErrorCategory.Erased);
	}

	[Fact]
	async Task Passkey_creation_options_answer_the_ceremony()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		harness.PasskeyHandler.MakeCreationOptionsAsync(Arg.Any<PasskeyUserEntity>(), Arg.Any<HttpContext>())
			.Returns(new PasskeyCreationOptionsResult { CreationOptionsJson = "{}", AttestationState = "state" });

		var outcome = (await harness.RunAsync(manager => manager.Outcome
			.MakePasskeyCreationOptionsAsync(harness.User, Cancellation)
			.AsTask())).Value.ShouldNotBeNull();

		outcome.TryGetValue(out Success<PasskeyCeremony> ceremony).ShouldBeTrue();
		ceremony.Value.OptionsJson.ShouldBe("{}");
		harness.AttestationProtector.Unprotect(ceremony.Value.State).ShouldBe("state");
	}

	[Fact]
	async Task A_verified_attestation_answers_the_result_and_a_failed_one_Validation_with_the_fixed_text()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var state = harness.AttestationProtector.Protect("state", TimeSpan.FromMinutes(5));
		var verified = PasskeyAttestationResult.Success(TestPasskeys.Info([0x0A]),
			new() { Id = harness.UserId, Name = "user@example.com", DisplayName = "user@example.com" });
		harness.PasskeyHandler.PerformAttestationAsync(Arg.Is<PasskeyAttestationContext>(c => c.CredentialJson == "good"))
			.Returns(verified);
		harness.PasskeyHandler.PerformAttestationAsync(Arg.Is<PasskeyAttestationContext>(c => c.CredentialJson == "bad"))
			.Returns(PasskeyAttestationResult.Fail(new PasskeyException("The origin 'https://evil.example' is not allowed.")));

		var good = await AttestAsync(harness, "good", state);
		var bad = await AttestAsync(harness, "bad", state);

		good.TryGetValue(out Success<PasskeyAttestationResult> success).ShouldBeTrue();
		success.Value.ShouldBeSameAs(verified);
		bad.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Validation);
		failed.Problem.Errors.Values.SelectMany(static messages => messages)
			.ShouldBe(["The passkey could not be verified. Try again."]);
	}

	[Fact]
	async Task A_stock_manager_fails_loud_on_the_passkey_methods()
	{
		NorseUser user = new() { UserName = "user@example.com", Email = "user@example.com" };

		await Should.ThrowAsync<InvalidOperationException>(async () =>
			await _signInManager.Outcome.MakePasskeyCreationOptionsAsync(user, Cancellation));
		await Should.ThrowAsync<InvalidOperationException>(async () =>
			await _signInManager.Outcome.PerformPasskeyAttestationAsync("{}", "state", Cancellation));
		await Should.ThrowAsync<InvalidOperationException>(async () =>
			await _signInManager.Outcome.MakePasskeyRequestOptionsAsync(Cancellation));
		await Should.ThrowAsync<InvalidOperationException>(async () =>
			await _signInManager.Outcome.PasskeyAssertionSignInAsync("{}", "state", false, Cancellation));
	}

	[Fact]
	async Task Passkey_request_options_answer_the_ceremony()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		harness.PasskeyHandler.MakeRequestOptionsAsync(Arg.Any<NorseUser?>(), Arg.Any<HttpContext>())
			.Returns(new PasskeyRequestOptionsResult { RequestOptionsJson = "{}", AssertionState = "state" });

		var outcome = (await harness.RunAsync(manager => manager.Outcome
			.MakePasskeyRequestOptionsAsync(Cancellation)
			.AsTask())).Value.ShouldNotBeNull();

		outcome.TryGetValue(out Success<PasskeyCeremony> ceremony).ShouldBeTrue();
		ceremony.Value.OptionsJson.ShouldBe("{}");
		harness.AssertionProtector.Unprotect(ceremony.Value.State).ShouldBe("state");
	}

	[Fact]
	async Task Passkey_assertion_sign_in_states_map_like_password_sign_in()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		harness.PasskeyHandler.PerformAssertionAsync(Arg.Is<PasskeyAssertionContext>(c => c.CredentialJson == "good"))
			.Returns(PasskeyAssertionResult.Success(TestPasskeys.Info([0x0A]), harness.User));
		harness.PasskeyHandler.PerformAssertionAsync(Arg.Is<PasskeyAssertionContext>(c => c.CredentialJson == "bad"))
			.Returns(PasskeyAssertionResult.Fail<NorseUser>(new PasskeyException("The origin 'https://evil.example' is not allowed.")));

		var good = await AssertPasskeyAsync(harness, "good", Protect(harness, "good-state"));
		var bad = await AssertPasskeyAsync(harness, "bad", Protect(harness, "bad-state"));
		var replay = await AssertPasskeyAsync(harness, "good", Protect(harness, "good-state"));
		harness.UserManager.IsLockedOutAsync(harness.User).Returns(true);
		var locked = await AssertPasskeyAsync(harness, "good", Protect(harness, "locked-state"));

		BaseRequest.ValueOf(good).ShouldBe(SignInCompletion.SignedIn);
		BaseRequest.ProblemOf(bad).Category.ShouldBe(ErrorCategory.InvalidCredentials);
		BaseRequest.ProblemOf(replay).Category.ShouldBe(ErrorCategory.InvalidCredentials);
		BaseRequest.ProblemOf(locked).Category.ShouldBe(ErrorCategory.LockedOut);
	}

	// The ledger's one-shot is over the unprotected state, so two protections of the same raw state are one challenge.
	static string Protect(TwoFactorHarness harness, string rawState) =>
		harness.AssertionProtector.Protect(rawState, TimeSpan.FromMinutes(5));

	static async Task<Outcome<SignInCompletion>> AssertPasskeyAsync(TwoFactorHarness harness, string credentialJson,
		string state) =>
		(await harness.RunAsync(manager => manager.Outcome
			.PasskeyAssertionSignInAsync(credentialJson, state, false, Cancellation)
			.AsTask())).Value.ShouldNotBeNull();

	static async Task<Outcome<PasskeyAttestationResult>> AttestAsync(TwoFactorHarness harness, string credentialJson,
		string state) =>
		(await harness.RunAsync(manager => manager.Outcome
			.PerformPasskeyAttestationAsync(credentialJson, state, Cancellation)
			.AsTask())).Value.ShouldNotBeNull();

	void AnswerExternal(string providerKey, SignInResult result) =>
		_signInManager.ExternalLoginSignInAsync("Provider", providerKey, false, false).Returns(result);

	async Task<Outcome<SignInCompletion>> ExternalAsync(string providerKey) =>
		await _signInManager.Outcome.ExternalLoginSignInAsync("Provider", providerKey, false, Cancellation);

	static async Task<string> ParkChallengeAsync(TwoFactorHarness harness) =>
		(await harness.RunAsync(manager => manager.PasswordSignInAsync(harness.User, TwoFactorHarness.Password,
			isPersistent: false, lockoutOnFailure: false))).Token.ShouldNotBeNull();

	static async Task<Outcome<string>> ChallengeAsync(TwoFactorHarness harness, string token, string code) =>
		(await harness.RunAsync(manager => manager.Outcome
			.TwoFactorChallengeSignInAsync(token, code, rememberClient: false, Cancellation)
			.AsTask())).Value.ShouldNotBeNull();

	static async Task<Outcome<string>> RecoveryAsync(TwoFactorHarness harness, string token, string code) =>
		(await harness.RunAsync(manager => manager.Outcome
			.RecoveryCodeChallengeSignInAsync(token, code, Cancellation)
			.AsTask())).Value.ShouldNotBeNull();

	static ErrorCategory CategoryOf<T>(Outcome<T> outcome) where T : notnull
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem.Category;
	}

	static string LandingOf(Outcome<string> outcome)
	{
		outcome.TryGetValue(out Success<string> success).ShouldBeTrue();
		return success.Value;
	}

	static SignInCompletion CompletionOf(Outcome<SignInCompletion> outcome)
	{
		outcome.TryGetValue(out Success<SignInCompletion> success).ShouldBeTrue();
		return success.Value;
	}

	void Answer(string userName, SignInResult result) =>
		_signInManager.PasswordSignInAsync(userName, "pw", false, true).Returns(result);

	async Task<ErrorCategory> Category(string userName)
	{
		var outcome = await _signInManager.Outcome.PasswordSignInAsync(userName, "pw", false, true, Cancellation);
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem.Category;
	}

	async Task<SignInCompletion> Completion(string userName)
	{
		var outcome = await _signInManager.Outcome.PasswordSignInAsync(userName, "pw", false, true, Cancellation);
		outcome.TryGetValue(out Success<SignInCompletion> success).ShouldBeTrue();
		return success.Value;
	}
}
