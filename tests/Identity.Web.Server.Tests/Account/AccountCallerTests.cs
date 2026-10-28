using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests.Account;

/// <summary>
///     <see cref="AccountCaller" /> resolves the caller from the principal, never the request: the user it names, a
///     principal naming no user as <see cref="ErrorCategory.NotFound" />, and an erased subject as
///     <see cref="ErrorCategory.Erased" /> with its receipt.
/// </summary>
public sealed class AccountCallerTests
{
	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly NorseUser _user = new() { UserName = "user@example.com", Email = "user@example.com" };

	public AccountCallerTests() =>
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>())
			.Returns(call => call.Arg<ClaimsPrincipal>().FindFirstValue(ClaimTypes.NameIdentifier) == _user.Id.ToString()
				? _user
				: null);

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Answers_the_user_the_principal_names()
	{
		AccountCaller caller = new(FakePrincipal.For(_user.Id), _userManager);

		var outcome = await caller.ResolveAsync(Cancellation);

		outcome.TryGetValue(out Success<NorseUser> success).ShouldBeTrue();
		success.Value.ShouldBeSameAs(_user);
	}

	[Fact]
	async Task A_principal_naming_no_user_answers_NotFound()
	{
		AccountCaller caller = new(FakePrincipal.Empty(), _userManager);

		ProblemOf(await caller.ResolveAsync(Cancellation)).Category.ShouldBe(ErrorCategory.NotFound);
	}

	[Fact]
	async Task An_erased_subject_answers_Erased_with_its_receipt()
	{
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).ThrowsAsync(new KeyDestroyedException(receipt));
		AccountCaller caller = new(FakePrincipal.For(_user.Id), _userManager);

		var problem = ProblemOf(await caller.ResolveAsync(Cancellation));

		problem.Category.ShouldBe(ErrorCategory.Erased);
		problem.Receipt.ShouldBe(receipt);
	}

	// T3-35: the one re-read-and-refresh after a rotating write; the refresh uses the instance read afresh, never the
	// as-read one, which a failed or indeterminate flush may have poisoned.
	[Fact]
	async Task A_refresh_after_a_rotation_re_reads_the_user_and_answers_the_url()
	{
		NorseUser reread = new() { Id = _user.Id, UserName = _user.UserName, Email = _user.Email };
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(reread);
		var signInManager = MockSignInManager.Create();
		var accessor = BaseRequest.Accessor();
		AccountCaller caller = new(FakePrincipal.For(_user.Id), _userManager);

		var outcome = await caller.RefreshFromReReadAsync(signInManager, BaseRequest.Completion(accessor),
			"/base/Account/Manage/TwoFactorAuthentication", Cancellation);

		BaseRequest.ValueOf(outcome).NextUrl.ShouldBe("/base/Account/Manage/TwoFactorAuthentication");
		await signInManager.Received(1).RefreshSignInAsync(Arg.Is<NorseUser>(user => ReferenceEquals(user, reread)));
	}

	[Fact]
	async Task A_failed_re_read_refreshes_nothing_and_passes_through()
	{
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).ThrowsAsync(new KeyDestroyedException(receipt));
		var signInManager = MockSignInManager.Create();
		var accessor = BaseRequest.Accessor();
		AccountCaller caller = new(FakePrincipal.For(_user.Id), _userManager);

		var outcome = await caller.RefreshFromReReadAsync(signInManager, BaseRequest.Completion(accessor),
			"/base/Account/Manage/TwoFactorAuthentication", Cancellation);

		BaseRequest.ProblemOf(outcome).Category.ShouldBe(ErrorCategory.Erased);
		await signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	static Problem ProblemOf(Outcome<NorseUser> outcome)
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem;
	}
}
