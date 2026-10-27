using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
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
	async Task Challenge_sign_in_states_map_like_password_sign_in()
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
		CompletionOf(rightCode).ShouldBe(SignInCompletion.SignedIn);
		CompletionOf(rightRecoveryCode).ShouldBe(SignInCompletion.SignedIn);
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

	static async Task<string> ParkChallengeAsync(TwoFactorHarness harness) =>
		(await harness.RunAsync(manager => manager.PasswordSignInAsync(harness.User, TwoFactorHarness.Password,
			isPersistent: false, lockoutOnFailure: false))).Token.ShouldNotBeNull();

	static async Task<Outcome<SignInCompletion>> ChallengeAsync(TwoFactorHarness harness, string token, string code) =>
		(await harness.RunAsync(manager => manager.Outcome
			.TwoFactorChallengeSignInAsync(token, code, rememberClient: false, Cancellation)
			.AsTask())).Value.ShouldNotBeNull();

	static async Task<Outcome<SignInCompletion>> RecoveryAsync(TwoFactorHarness harness, string token, string code) =>
		(await harness.RunAsync(manager => manager.Outcome
			.RecoveryCodeChallengeSignInAsync(token, code, Cancellation)
			.AsTask())).Value.ShouldNotBeNull();

	static ErrorCategory CategoryOf(Outcome<SignInCompletion> outcome)
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem.Category;
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
