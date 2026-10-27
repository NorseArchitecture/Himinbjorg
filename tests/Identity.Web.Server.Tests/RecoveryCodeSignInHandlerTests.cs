using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     <see cref="RecoveryCodeSignInHandler" /> over a real <see cref="NorseSignInManager" /> on
///     <see cref="TwoFactorHarness" />.
/// </summary>
public sealed class RecoveryCodeSignInHandlerTests
{
	const string WrongRecoveryCode = "wrong-code";

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Success_answers_the_app_root()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var token = await ParkChallengeAsync(harness);

		var outcome = await SignInAsync(harness, token, TwoFactorHarness.RecoveryCode);

		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldBe("/");
	}

	[Fact]
	async Task Every_refusal_collapses_onto_the_handlers_one_static_instance()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		harness.UserManager.RedeemTwoFactorRecoveryCodeAsync(harness.User, WrongRecoveryCode)
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().RecoveryCodeRedemptionFailed()));

		var wrongCodeToken = await ParkChallengeAsync(harness);
		var wrongCode = await SignInAsync(harness, wrongCodeToken, WrongRecoveryCode);

		var rotatedToken = await ParkChallengeAsync(harness);
		harness.Stamp = Guid.NewGuid().ToString();
		var stampMismatch = await SignInAsync(harness, rotatedToken, TwoFactorHarness.RecoveryCode);

		var erasedToken = await ParkChallengeAsync(harness);
		harness.UserManager.FindByIdAsync(harness.UserId)
			.ThrowsAsync(new KeyDestroyedException(new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch)));
		var erased = await SignInAsync(harness, erasedToken, TwoFactorHarness.RecoveryCode);

		var first = ProblemOf(wrongCode);
		ProblemOf(stampMismatch).ShouldBeSameAs(first);
		ProblemOf(erased).ShouldBeSameAs(first);
		first.Category.ShouldBe(ErrorCategory.InvalidCredentials);
		first.Errors.Keys.ShouldBe([string.Empty]);
		first.Errors[string.Empty].ShouldBe(["Invalid recovery code entered."]);
	}

	static async Task<string> ParkChallengeAsync(TwoFactorHarness harness) =>
		(await harness.RunAsync(manager => manager.PasswordSignInAsync(harness.User, TwoFactorHarness.Password,
			isPersistent: false, lockoutOnFailure: false))).Token.ShouldNotBeNull();

	static async Task<Outcome<NavigationResult>> SignInAsync(TwoFactorHarness harness, string token, string code) =>
		(await harness.RunAsync(manager =>
		{
			var accessor = harness.Services.GetRequiredService<IHttpContextAccessor>();
			RecoveryCodeSignInHandler handler = new(manager, new(harness.DeferredSignIn, accessor), accessor);
			return handler.Handle(new(new RecoveryCodeSignInRequest { Challenge = token, RecoveryCode = code }),
				Cancellation).AsTask();
		})).Value.ShouldNotBeNull();

	static Problem ProblemOf(Outcome<NavigationResult> outcome)
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem;
	}
}
