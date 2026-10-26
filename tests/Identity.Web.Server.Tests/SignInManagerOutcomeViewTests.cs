using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

/// <summary><c>signInManager.Outcome</c> (2026-10-24 explicit-writes spec §4.12), against a substituted manager.</summary>
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
