using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.TwoFactor;

namespace Norse.Identity.Web.Server.Tests.TwoFactor;

/// <summary>
///     <see cref="ResetAuthenticatorHandler" />: disable, then reset the key, then refresh, answering the setup page
///     with <c>authenticator-reset</c>. Both writes rotate the stamp, so once the disable succeeded or is indeterminate
///     any later failure re-reads the user, refreshes from that instance and answers the two-factor page with no status
///     key (T3-35); a definite disable failure writes no key and refreshes nothing.
/// </summary>
public sealed class ResetAuthenticatorHandlerTests
{
	static readonly IdentityResult _indeterminate =
		IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome });

	readonly FakeLogger<ResetAuthenticatorHandler> _logger = new();
	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly SignInManager<NorseUser> _signInManager = MockSignInManager.Create();
	readonly NorseUser _user = new() { Id = Guid.CreateVersion7(), UserName = "user@example.com", Email = "user@example.com" };
	readonly NorseUser _reread = new() { UserName = "user@example.com", Email = "user@example.com" };

	public ResetAuthenticatorHandlerTests()
	{
		_reread.Id = _user.Id;
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user, _reread);
		_userManager.SetTwoFactorEnabledAsync(_user, false).Returns(IdentityResult.Success);
		_userManager.ResetAuthenticatorKeyAsync(_user).Returns(IdentityResult.Success);
	}

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Reset_disables_resets_refreshes_and_answers_the_status_url()
	{
		BaseRequest.ValueOf(await HandleAsync()).NextUrl
			.ShouldBe("/base/Account/Manage/EnableAuthenticator?status=authenticator-reset");
		Received.InOrder(() =>
		{
			_userManager.SetTwoFactorEnabledAsync(_user, false);
			_userManager.ResetAuthenticatorKeyAsync(_user);
			_signInManager.RefreshSignInAsync(_user);
		});
		await _userManager.Received(1).GetUserAsync(Arg.Any<ClaimsPrincipal>());
	}

	[Fact]
	async Task A_failed_disable_writes_no_key_and_refreshes_nothing()
	{
		_userManager.SetTwoFactorEnabledAsync(_user, false)
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().ConcurrencyFailure()));

		BaseRequest.ProblemOf(await HandleAsync()).Category.ShouldBe(ErrorCategory.Conflict);
		await _userManager.DidNotReceiveWithAnyArgs().ResetAuthenticatorKeyAsync(default!);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task An_indeterminate_disable_refreshes_and_answers_the_two_factor_page()
	{
		_userManager.SetTwoFactorEnabledAsync(_user, false).Returns(_indeterminate);

		BaseRequest.ValueOf(await HandleAsync()).NextUrl.ShouldBe("/base/Account/Manage/TwoFactorAuthentication");
		await _userManager.DidNotReceiveWithAnyArgs().ResetAuthenticatorKeyAsync(default!);
		await _signInManager.Received(1).RefreshSignInAsync(_reread);
	}

	[Theory]
	[InlineData("Unmapped")]
	[InlineData(NorseIdentityErrorCodes.IndeterminateOutcome)]
	async Task A_failed_key_reset_after_disabling_still_refreshes(string errorCode)
	{
		_userManager.ResetAuthenticatorKeyAsync(_user).Returns(IdentityResult.Failed(new IdentityError { Code = errorCode }));

		BaseRequest.ValueOf(await HandleAsync()).NextUrl.ShouldBe("/base/Account/Manage/TwoFactorAuthentication");
		await _signInManager.Received(1).RefreshSignInAsync(_reread);
	}

	// The store rethrows a definite database failure (spec §4.8): the key was not replaced, but the disable committed.
	[Fact]
	async Task A_key_reset_that_throws_a_definite_database_failure_still_refreshes()
	{
		SimulatedDbException thrown = new("Simulated definite failure.");
		_userManager.ResetAuthenticatorKeyAsync(_user).ThrowsAsync(thrown);

		BaseRequest.ValueOf(await HandleAsync()).NextUrl.ShouldBe("/base/Account/Manage/TwoFactorAuthentication");
		await _signInManager.Received(1).RefreshSignInAsync(_reread);
		// Handled, never silent: the failure is logged with the exception, at Warning or above.
		var logged = _logger.Collector.GetSnapshot().ShouldHaveSingleItem();
		((int)logged.Level).ShouldBeGreaterThanOrEqualTo((int)LogLevel.Warning);
		logged.Exception.ShouldBeSameAs(thrown);
	}

	[Fact]
	async Task Each_post_failure_refresh_uses_a_re_read_user()
	{
		_userManager.ResetAuthenticatorKeyAsync(_user).Returns(_indeterminate);

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
		await _userManager.DidNotReceiveWithAnyArgs().SetTwoFactorEnabledAsync(default!, default);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	ValueTask<Outcome<NavigationResult>> HandleAsync()
	{
		var accessor = BaseRequest.Accessor();
		ResetAuthenticatorHandler handler = new(new AccountCaller(FakePrincipal.For(_user.Id), _userManager), _userManager,
			_signInManager, BaseRequest.Completion(accessor), accessor, _logger);
		return handler.Handle(new(Unit.Value), Cancellation);
	}
}
