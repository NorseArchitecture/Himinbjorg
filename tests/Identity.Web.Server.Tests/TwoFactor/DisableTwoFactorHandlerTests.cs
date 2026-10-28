using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.TwoFactor;

namespace Norse.Identity.Web.Server.Tests.TwoFactor;

/// <summary>
///     <see cref="DisableTwoFactorHandler" />: a caller with two-factor already off is refused and nothing is written;
///     otherwise the disable rotates the stamp, so the sign-in is refreshed and the answer is the two-factor page with
///     <c>two-factor-disabled</c>. An indeterminate disable re-reads the user and refreshes from that instance (T3-35);
///     a definite one refreshes nothing.
/// </summary>
public sealed class DisableTwoFactorHandlerTests
{
	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly SignInManager<NorseUser> _signInManager = MockSignInManager.Create();
	readonly NorseUser _user = new() { Id = Guid.CreateVersion7(), UserName = "user@example.com", Email = "user@example.com" };
	readonly NorseUser _reread = new() { UserName = "user@example.com", Email = "user@example.com" };

	public DisableTwoFactorHandlerTests()
	{
		_reread.Id = _user.Id;
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user, _reread);
		_userManager.GetTwoFactorEnabledAsync(_user).Returns(true);
		_userManager.SetTwoFactorEnabledAsync(_user, false).Returns(IdentityResult.Success);
	}

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Disabling_when_already_off_answers_Validation_and_writes_nothing()
	{
		_userManager.GetTwoFactorEnabledAsync(_user).Returns(false);

		var problem = BaseRequest.ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors.Values.SelectMany(static messages => messages).ShouldBe(["Two-factor authentication is not enabled."]);
		await _userManager.DidNotReceiveWithAnyArgs().SetTwoFactorEnabledAsync(default!, default);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task Disabling_refreshes_the_sign_in_and_answers_the_status_url()
	{
		BaseRequest.ValueOf(await HandleAsync()).NextUrl
			.ShouldBe("/base/Account/Manage/TwoFactorAuthentication?status=two-factor-disabled");
		Received.InOrder(() =>
		{
			_userManager.SetTwoFactorEnabledAsync(_user, false);
			_signInManager.RefreshSignInAsync(_user);
		});
		await _userManager.Received(1).GetUserAsync(Arg.Any<ClaimsPrincipal>());
	}

	[Fact]
	async Task An_indeterminate_disable_refreshes_and_answers_the_two_factor_page()
	{
		_userManager.SetTwoFactorEnabledAsync(_user, false)
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));

		BaseRequest.ValueOf(await HandleAsync()).NextUrl.ShouldBe("/base/Account/Manage/TwoFactorAuthentication");
		await _userManager.Received(2).GetUserAsync(Arg.Any<ClaimsPrincipal>());
		await _signInManager.Received(1).RefreshSignInAsync(Arg.Is<NorseUser>(user => ReferenceEquals(user, _reread)));
		await _signInManager.DidNotReceive().RefreshSignInAsync(Arg.Is<NorseUser>(user => ReferenceEquals(user, _user)));
	}

	[Fact]
	async Task A_definite_disable_failure_refreshes_nothing()
	{
		_userManager.SetTwoFactorEnabledAsync(_user, false)
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().ConcurrencyFailure()));

		BaseRequest.ProblemOf(await HandleAsync()).Category.ShouldBe(ErrorCategory.Conflict);
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
		await _userManager.DidNotReceiveWithAnyArgs().SetTwoFactorEnabledAsync(default!, default);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	ValueTask<Outcome<NavigationResult>> HandleAsync()
	{
		var accessor = BaseRequest.Accessor();
		DisableTwoFactorHandler handler = new(new AccountCaller(FakePrincipal.For(_user.Id), _userManager), _userManager,
			_signInManager, BaseRequest.Completion(accessor), accessor);
		return handler.Handle(new(Unit.Value), Cancellation);
	}
}
