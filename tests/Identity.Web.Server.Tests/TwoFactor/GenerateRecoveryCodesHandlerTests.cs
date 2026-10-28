using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.TwoFactor;

namespace Norse.Identity.Web.Server.Tests.TwoFactor;

/// <summary>
///     <see cref="GenerateRecoveryCodesHandler" />: a caller with two-factor off is refused and nothing is written;
///     otherwise ten fresh codes replace the old set and come back in place. Replacing codes never rotates the stamp,
///     so nothing is refreshed, and an indeterminate replacement passes through for the caller to see.
/// </summary>
public sealed class GenerateRecoveryCodesHandlerTests
{
	static readonly string[] _codes = [.. Enumerable.Range(0, 10).Select(static i => $"code-{i:00}")];

	readonly UserManager<NorseUser> _userManager = MockUserManager.CreateLossless();
	readonly SignInManager<NorseUser> _signInManager = MockSignInManager.Create();
	readonly NorseUser _user = new() { Id = Guid.CreateVersion7(), UserName = "user@example.com", Email = "user@example.com" };

	public GenerateRecoveryCodesHandlerTests()
	{
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user);
		_userManager.GetTwoFactorEnabledAsync(_user).Returns(true);
		Replacement.ReplaceRecoveryCodesAsync(_user, 10).Returns((IdentityResult.Success, _codes));
	}

	IRecoveryCodeReplacement Replacement => (IRecoveryCodeReplacement)_userManager;

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Generating_when_off_answers_Validation_and_writes_nothing()
	{
		_userManager.GetTwoFactorEnabledAsync(_user).Returns(false);

		var problem = BaseRequest.ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors.Values.SelectMany(static messages => messages)
			.ShouldBe(["Cannot generate recovery codes because two-factor authentication is not enabled."]);
		await Replacement.DidNotReceiveWithAnyArgs().ReplaceRecoveryCodesAsync(default!, default);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task Generating_returns_ten_codes_and_refreshes_nothing()
	{
		BaseRequest.ValueOf(await HandleAsync()).RecoveryCodes.ShouldBe(_codes);
		await Replacement.Received(1).ReplaceRecoveryCodesAsync(_user, 10);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task An_indeterminate_generation_answers_Indeterminate()
	{
		Replacement.ReplaceRecoveryCodesAsync(_user, 10).Returns((
			IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }), _codes));

		BaseRequest.ProblemOf(await HandleAsync()).Category.ShouldBe(ErrorCategory.Indeterminate);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task An_erased_subject_answers_Erased()
	{
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).ThrowsAsync(new KeyDestroyedException(receipt));

		var problem = BaseRequest.ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.Erased);
		problem.Receipt.ShouldBeSameAs(receipt);
		await Replacement.DidNotReceiveWithAnyArgs().ReplaceRecoveryCodesAsync(default!, default);
	}

	ValueTask<Outcome<RecoveryCodesResponse>> HandleAsync()
	{
		GenerateRecoveryCodesHandler handler = new(new AccountCaller(FakePrincipal.For(_user.Id), _userManager), _userManager);
		return handler.Handle(new(Unit.Value), Cancellation);
	}
}
