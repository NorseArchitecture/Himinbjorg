using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.TwoFactor;

namespace Norse.Identity.Web.Server.Tests.TwoFactor;

/// <summary>
///     <see cref="EnableAuthenticatorHandler" />: the code is verified before anything is written; enabling rotates the
///     stamp, so the sign-in is refreshed and the answer navigates; ten codes are issued only when none remain and ride
///     a one-shot handoff sealed with the stamp read after the writes. Once the rotating write succeeded or is
///     indeterminate, a later failure re-reads the user and refreshes from that instance (T3-35); a definite failure
///     before it refreshes nothing.
/// </summary>
public sealed class EnableAuthenticatorHandlerTests
{
	const string Code = "123456";

	static readonly string[] _codes = [.. Enumerable.Range(0, 10).Select(static i => $"code-{i:00}")];

	readonly FakeLogger<EnableAuthenticatorHandler> _logger = new();
	readonly EphemeralDataProtectionProvider _dataProtection = new();
	readonly UserManager<NorseUser> _userManager = MockUserManager.CreateLossless();
	readonly SignInManager<NorseUser> _signInManager = MockSignInManager.Create();
	readonly NorseUser _user = new() { Id = Guid.CreateVersion7(), UserName = "user@example.com", Email = "user@example.com" };
	readonly NorseUser _reread = new() { UserName = "user@example.com", Email = "user@example.com" };

	public EnableAuthenticatorHandlerTests()
	{
		_reread.Id = _user.Id;
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user, _reread);
		_userManager.VerifyTwoFactorTokenAsync(_user, TokenOptions.DefaultAuthenticatorProvider, Code).Returns(true);
		_userManager.SetTwoFactorEnabledAsync(_user, true).Returns(IdentityResult.Success);
		_userManager.CountRecoveryCodesAsync(_user).Returns(0);
		_userManager.GetUserIdAsync(_user).Returns(_user.Id.ToString());
		_userManager.GetSecurityStampAsync(_user).Returns("stamp-after");
		Replacement.ReplaceRecoveryCodesAsync(_user, 10).Returns((IdentityResult.Success, _codes));
	}

	IRecoveryCodeReplacement Replacement => (IRecoveryCodeReplacement)_userManager;

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Theory]
	[InlineData("12345")]
	[InlineData("654321")]
	async Task An_invalid_code_answers_Validation_and_enables_nothing(string code)
	{
		var problem = BaseRequest.ProblemOf(await HandleAsync(code));

		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors.Keys.ShouldBe([nameof(EnableAuthenticatorRequest.Code)]);
		problem.Errors[nameof(EnableAuthenticatorRequest.Code)].ShouldBe(["Verification code is invalid."]);
		await _userManager.DidNotReceiveWithAnyArgs().SetTwoFactorEnabledAsync(default!, default);
		await Replacement.DidNotReceiveWithAnyArgs().ReplaceRecoveryCodesAsync(default!, default);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Theory]
	[InlineData("123 456")]
	[InlineData("123-456")]
	[InlineData(" 12-34 56")]
	async Task Spaces_and_hyphens_are_stripped_before_the_code_is_verified(string typed)
	{
		await HandleAsync(typed);

		await _userManager.Received(1).VerifyTwoFactorTokenAsync(_user, TokenOptions.DefaultAuthenticatorProvider, Code);
		await _userManager.Received(1).SetTwoFactorEnabledAsync(_user, true);
	}

	[Fact]
	async Task A_first_enable_refreshes_the_sign_in_and_hands_off_ten_codes()
	{
		var next = BaseRequest.ValueOf(await HandleAsync()).NextUrl;

		next.ShouldStartWith("/base/Account/Manage/ShowRecoveryCodes?handoff=");
		var handoff = QueryHelpers.ParseQuery(new Uri(new("https://example.test"), next).Query)["handoff"].ToString();
		RecoveryCodesHandoff.TryUnprotect(Protector(), handoff, out var opened).ShouldBeTrue();
		opened.UserId.ShouldBe(_user.Id.ToString());
		opened.SecurityStamp.ShouldBe("stamp-after");
		opened.Codes.ShouldBe(_codes);
		await Replacement.Received(1).ReplaceRecoveryCodesAsync(_user, 10);
		Received.InOrder(() =>
		{
			_userManager.SetTwoFactorEnabledAsync(_user, true);
			Replacement.ReplaceRecoveryCodesAsync(_user, 10);
			_userManager.GetSecurityStampAsync(_user);
			_signInManager.RefreshSignInAsync(_user);
		});
	}

	[Fact]
	async Task An_enable_with_existing_codes_refreshes_and_answers_the_verified_url()
	{
		_userManager.CountRecoveryCodesAsync(_user).Returns(3);

		BaseRequest.ValueOf(await HandleAsync()).NextUrl
			.ShouldBe("/base/Account/Manage/TwoFactorAuthentication?status=authenticator-verified");
		await Replacement.DidNotReceiveWithAnyArgs().ReplaceRecoveryCodesAsync(default!, default);
		await _signInManager.Received(1).RefreshSignInAsync(_user);
	}

	[Theory]
	[InlineData("Unmapped")]
	[InlineData(NorseIdentityErrorCodes.IndeterminateOutcome)]
	async Task A_failed_code_replacement_after_enabling_refreshes_and_answers_the_codes_failed_url(string errorCode)
	{
		Replacement.ReplaceRecoveryCodesAsync(_user, 10)
			.Returns((IdentityResult.Failed(new IdentityError { Code = errorCode }), _codes));

		BaseRequest.ValueOf(await HandleAsync()).NextUrl
			.ShouldBe("/base/Account/Manage/TwoFactorAuthentication?status=recovery-codes-failed");
		await _signInManager.Received(1).RefreshSignInAsync(_reread);
		await _signInManager.DidNotReceive().RefreshSignInAsync(_user);
	}

	// The store rethrows a definite database failure (spec §4.8): the codes were not written, but the enable committed.
	[Fact]
	async Task A_code_step_that_throws_a_definite_database_failure_refreshes_and_answers_the_codes_failed_url()
	{
		SimulatedDbException thrown = new("Simulated definite failure.");
		Replacement.ReplaceRecoveryCodesAsync(_user, 10).ThrowsAsync(thrown);

		BaseRequest.ValueOf(await HandleAsync()).NextUrl
			.ShouldBe("/base/Account/Manage/TwoFactorAuthentication?status=recovery-codes-failed");
		await _signInManager.Received(1).RefreshSignInAsync(_reread);
		// Handled, never silent: the failure is logged with the exception, at Warning or above.
		var logged = _logger.Collector.GetSnapshot().ShouldHaveSingleItem();
		((int)logged.Level).ShouldBeGreaterThanOrEqualTo((int)LogLevel.Warning);
		logged.Exception.ShouldBeSameAs(thrown);
	}

	[Fact]
	async Task An_indeterminate_enable_refreshes_and_answers_the_two_factor_page()
	{
		_userManager.SetTwoFactorEnabledAsync(_user, true)
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));

		BaseRequest.ValueOf(await HandleAsync()).NextUrl.ShouldBe("/base/Account/Manage/TwoFactorAuthentication");
		await _signInManager.Received(1).RefreshSignInAsync(_reread);
		await _userManager.DidNotReceiveWithAnyArgs().CountRecoveryCodesAsync(default!);
		await Replacement.DidNotReceiveWithAnyArgs().ReplaceRecoveryCodesAsync(default!, default);
	}

	[Fact]
	async Task A_definite_enable_failure_refreshes_nothing()
	{
		_userManager.SetTwoFactorEnabledAsync(_user, true)
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().ConcurrencyFailure()));

		BaseRequest.ProblemOf(await HandleAsync()).Category.ShouldBe(ErrorCategory.Conflict);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
		await Replacement.DidNotReceiveWithAnyArgs().ReplaceRecoveryCodesAsync(default!, default);
		await _userManager.Received(1).GetUserAsync(Arg.Any<ClaimsPrincipal>());
	}

	// The substitute answers the as-read instance first and a fresh one second: the refresh after a failure must use
	// the second, never the possibly poisoned first.
	[Fact]
	async Task Each_post_failure_refresh_uses_a_re_read_user()
	{
		_userManager.SetTwoFactorEnabledAsync(_user, true)
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));

		await HandleAsync();

		await _userManager.Received(2).GetUserAsync(Arg.Any<ClaimsPrincipal>());
		await _signInManager.Received(1).RefreshSignInAsync(Arg.Is<NorseUser>(user => ReferenceEquals(user, _reread)));
		await _signInManager.DidNotReceive().RefreshSignInAsync(Arg.Is<NorseUser>(user => ReferenceEquals(user, _user)));
	}

	[Fact]
	async Task An_erased_subject_answers_Erased()
	{
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).ThrowsAsync(new KeyDestroyedException(receipt));

		var problem = BaseRequest.ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.Erased);
		problem.Receipt.ShouldBeSameAs(receipt);
		await _userManager.DidNotReceiveWithAnyArgs().VerifyTwoFactorTokenAsync(default!, default!, default!);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	ITimeLimitedDataProtector Protector() =>
		_dataProtection.CreateProtector(RecoveryCodesHandoff.Purpose).ToTimeLimitedDataProtector();

	ValueTask<Outcome<NavigationResult>> HandleAsync(string code = Code)
	{
		var accessor = BaseRequest.Accessor();
		EnableAuthenticatorHandler handler = new(new AccountCaller(FakePrincipal.For(_user.Id), _userManager), _userManager,
			_signInManager, BaseRequest.Completion(accessor), accessor, _dataProtection, _logger);
		return handler.Handle(new(new() { Code = code }), Cancellation);
	}
}
