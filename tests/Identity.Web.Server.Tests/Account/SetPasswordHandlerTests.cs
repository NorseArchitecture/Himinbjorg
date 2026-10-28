using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests.Account;

public sealed class SetPasswordHandlerTests
{
	const string NewPassword = "Replacement-1!";
	const string StashedSignInKey = "stashed-refresh";

	readonly IdentityErrorDescriber _describer = new();
	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly SignInManager<NorseUser> _signInManager = MockSignInManager.Create();
	readonly NorseUser _user = new() { UserName = "user@example.com", Email = "user@example.com" };

	public SetPasswordHandlerTests()
	{
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user);
		_userManager.AddPasswordAsync(_user, NewPassword).Returns(IdentityResult.Success);
	}

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Success_refreshes_the_sign_in_and_answers_the_status_url()
	{
		NextUrlOf(await HandleAsync()).ShouldBe("/base/Account/Manage/ChangePassword?status=password-set");
		await _userManager.Received(1).AddPasswordAsync(_user, NewPassword);
		await _signInManager.Received(1).RefreshSignInAsync(_user);
	}

	[Fact]
	async Task An_account_that_already_has_a_password_answers_Conflict()
	{
		var already = _describer.UserAlreadyHasPassword();
		_userManager.AddPasswordAsync(_user, NewPassword).Returns(IdentityResult.Failed(already));

		var problem = ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.Conflict);
		problem.Errors.Keys.ShouldBe([""]);
		problem.Errors[""].ShouldBe([already.Description]);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task Password_rule_failures_regroup_onto_the_new_password_field()
	{
		IdentityError tooShort = _describer.PasswordTooShort(12), digit = _describer.PasswordRequiresDigit();
		_userManager.AddPasswordAsync(_user, NewPassword).Returns(IdentityResult.Failed(tooShort, digit));

		var problem = ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors.Keys.ShouldBe([nameof(SetPasswordRequest.NewPassword)]);
		problem.Errors[nameof(SetPasswordRequest.NewPassword)]
			.ShouldBe([tooShort.Description, digit.Description], ignoreOrder: true);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task An_erasure_during_the_write_answers_Erased_with_its_receipt()
	{
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.AddPasswordAsync(_user, NewPassword).ThrowsAsync(new KeyDestroyedException(receipt));

		var problem = ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.Erased);
		problem.Receipt.ShouldBeSameAs(receipt);
		problem.Errors.ShouldBeEmpty();
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task A_refresh_on_a_started_response_answers_the_completion_url()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		harness.UserManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(harness.User);
		harness.UserManager.AddPasswordAsync(harness.User, NewPassword).Returns(IdentityResult.Success);
		harness.DeferredSignIn
			.StashSignIn(Arg.Any<string>(), Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>())
			.Returns(StashedSignInKey);
		harness.DeferredSignIn.BuildCompletionUrl(Arg.Any<string>(), Arg.Any<string>())
			.Returns(call =>
				$"/_auth/complete?key={call.ArgAt<string>(0)}&returnUrl={Uri.EscapeDataString(call.ArgAt<string>(1))}");
		var signedIn = await harness.RunAsync(manager =>
			manager.SignInWithClaimsAsync(harness.User, isPersistent: false, additionalClaims: []));
		var cookie = TwoFactorHarness.CookieOf(signedIn.SetCookieFor(".AspNetCore.Identity.Application")!);

		var probe = await harness.RunAsync(manager =>
		{
			var accessor = harness.Services.GetRequiredService<IHttpContextAccessor>();
			SetPasswordHandler handler = new(new AccountCaller(FakePrincipal.For(harness.User.Id), harness.UserManager),
				harness.UserManager, manager, new(harness.DeferredSignIn, accessor), accessor);
			return handler.Handle(new(new() { NewPassword = NewPassword }), Cancellation).AsTask();
		}, responseAlreadyStarted: true, cookie);

		probe.Exception.ShouldBeNull();
		probe.IdentityKey.ShouldBe(StashedSignInKey);
		NextUrlOf(probe.Value.ShouldNotBeNull())
			.ShouldBe(harness.DeferredSignIn.BuildCompletionUrl(StashedSignInKey,
				"/Account/Manage/ChangePassword?status=password-set"));
	}

	ValueTask<Outcome<NavigationResult>> HandleAsync()
	{
		DefaultHttpContext context = new();
		context.Request.PathBase = "/base";
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(context);
		SetPasswordHandler handler = new(new AccountCaller(FakePrincipal.For(_user.Id), _userManager),
			_userManager, _signInManager, new(Substitute.For<IDeferredSignIn>(), accessor), accessor);
		return handler.Handle(new(new() { NewPassword = NewPassword }), Cancellation);
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
