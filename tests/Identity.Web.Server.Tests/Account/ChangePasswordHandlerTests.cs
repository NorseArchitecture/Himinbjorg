using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests.Account;

public sealed class ChangePasswordHandlerTests
{
	const string OldPassword = "Current-1!";
	const string NewPassword = "Replacement-1!";

	readonly IdentityErrorDescriber _describer = new();
	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly SignInManager<NorseUser> _signInManager = MockSignInManager.Create();
	readonly NorseUser _user = new() { UserName = "user@example.com", Email = "user@example.com" };

	public ChangePasswordHandlerTests()
	{
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user);
		_userManager.ChangePasswordAsync(_user, OldPassword, NewPassword).Returns(IdentityResult.Success);
	}

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Success_refreshes_the_sign_in_and_answers_the_status_url()
	{
		NextUrlOf(await HandleAsync()).ShouldBe("/base/Account/Manage/ChangePassword?status=password-changed");
		await _userManager.Received(1).ChangePasswordAsync(_user, OldPassword, NewPassword);
		await _signInManager.Received(1).RefreshSignInAsync(_user);
	}

	[Fact]
	async Task A_wrong_current_password_lands_on_the_old_password_field_as_InvalidCredentials()
	{
		var mismatch = _describer.PasswordMismatch();
		_userManager.ChangePasswordAsync(_user, OldPassword, NewPassword).Returns(IdentityResult.Failed(mismatch));

		var problem = ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.InvalidCredentials);
		problem.Errors.Keys.ShouldBe([nameof(ChangePasswordRequest.OldPassword)]);
		problem.Errors[nameof(ChangePasswordRequest.OldPassword)].ShouldBe([mismatch.Description]);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task Password_rule_failures_regroup_onto_the_new_password_field()
	{
		IdentityError tooShort = _describer.PasswordTooShort(12), digit = _describer.PasswordRequiresDigit();
		_userManager.ChangePasswordAsync(_user, OldPassword, NewPassword).Returns(IdentityResult.Failed(tooShort, digit));

		var problem = ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors.Keys.ShouldBe([nameof(ChangePasswordRequest.NewPassword)]);
		problem.Errors[nameof(ChangePasswordRequest.NewPassword)]
			.ShouldBe([tooShort.Description, digit.Description], ignoreOrder: true);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task An_indeterminate_commit_passes_through()
	{
		_userManager.ChangePasswordAsync(_user, OldPassword, NewPassword)
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));

		ProblemOf(await HandleAsync()).Category.ShouldBe(ErrorCategory.Indeterminate);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task An_erased_subject_answers_Erased()
	{
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).ThrowsAsync(new KeyDestroyedException(receipt));

		var problem = ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.Erased);
		problem.Receipt.ShouldBeSameAs(receipt);
		await _userManager.DidNotReceiveWithAnyArgs().ChangePasswordAsync(default!, default!, default!);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task An_erasure_during_the_write_answers_Erased_with_its_receipt()
	{
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.ChangePasswordAsync(_user, OldPassword, NewPassword).ThrowsAsync(new KeyDestroyedException(receipt));

		var problem = ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.Erased);
		problem.Receipt.ShouldBeSameAs(receipt);
		problem.Errors.ShouldBeEmpty();
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	ValueTask<Outcome<NavigationResult>> HandleAsync()
	{
		DefaultHttpContext context = new();
		context.Request.PathBase = "/base";
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(context);
		ChangePasswordHandler handler = new(_userManager, _signInManager, FakePrincipal.For(_user.Id),
			new(Substitute.For<IDeferredSignIn>(), accessor), accessor);
		return handler.Handle(new(new() { OldPassword = OldPassword, NewPassword = NewPassword }), Cancellation);
	}

	static string NextUrlOf(Outcome<NavigationResult> outcome)
	{
		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		return success.Value.NextUrl;
	}

	static Problem ProblemOf(Outcome<NavigationResult> outcome)
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem;
	}
}
