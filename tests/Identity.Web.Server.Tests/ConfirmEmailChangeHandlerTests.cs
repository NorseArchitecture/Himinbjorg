using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

public sealed class ConfirmEmailChangeHandlerTests
{
	const string NewEmail = "renamed@example.com";
	const string Token = "change/token+with=padding";
	const string StashedSignInKey = "stashed-refresh";

	static readonly string _code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(Token));

	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly SignInManager<NorseUser> _signInManager = MockSignInManager.Create();
	readonly NorseUser _user = new() { UserName = "user@example.com", Email = "user@example.com" };

	public ConfirmEmailChangeHandlerTests()
	{
		_userManager.FindByIdAsync(_user.Id.ToString()).Returns(_user);
		_userManager.GetUserId(Arg.Any<ClaimsPrincipal>())
			.Returns(call => call.Arg<ClaimsPrincipal>().FindFirstValue(ClaimTypes.NameIdentifier));
		_userManager.ChangeEmailAsync(_user, NewEmail, Token).Returns(IdentityResult.Success);
	}

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task A_confirmed_change_by_the_same_user_refreshes_the_sign_in_and_answers_the_root()
	{
		var outcome = await HandleAsync(FakePrincipal.For(_user.Id));

		NextUrlOf(outcome).ShouldBe("/base/");
		await _userManager.Received(1).ChangeEmailAsync(_user, NewEmail, Token);
		await _signInManager.Received(1).RefreshSignInAsync(_user);
	}

	[Fact]
	async Task A_confirmed_change_for_another_user_does_not_refresh_the_callers_session()
	{
		var outcome = await HandleAsync(FakePrincipal.For(Guid.CreateVersion7()));

		NextUrlOf(outcome).ShouldBe("/base/Account/Login");
		await _userManager.Received(1).ChangeEmailAsync(_user, NewEmail, Token);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task An_anonymous_caller_is_treated_as_another_user()
	{
		var outcome = await HandleAsync(FakePrincipal.Empty());

		NextUrlOf(outcome).ShouldBe("/base/Account/Login");
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task A_duplicate_email_answers_Conflict()
	{
		_userManager.ChangeEmailAsync(_user, NewEmail, Token)
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().DuplicateEmail(NewEmail)));

		ProblemOf(await HandleAsync(FakePrincipal.For(_user.Id))).Category.ShouldBe(ErrorCategory.Conflict);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task An_invalid_token_answers_InvalidCredentials()
	{
		_userManager.ChangeEmailAsync(_user, NewEmail, Token)
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().InvalidToken()));

		ProblemOf(await HandleAsync(FakePrincipal.For(_user.Id))).Category.ShouldBe(ErrorCategory.InvalidCredentials);
		ProblemOf(await HandleAsync(FakePrincipal.For(_user.Id), "not*base64")).Category
			.ShouldBe(ErrorCategory.InvalidCredentials);
		await _userManager.Received(1).ChangeEmailAsync(Arg.Any<NorseUser>(), Arg.Any<string>(), Arg.Any<string>());
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	[Fact]
	async Task A_refresh_on_a_started_response_answers_the_completion_url()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		harness.UserManager.ChangeEmailAsync(harness.User, NewEmail, Token).Returns(IdentityResult.Success);
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
			ConfirmEmailChangeHandler handler = new(harness.UserManager, manager, FakePrincipal.For(harness.User.Id),
				new(harness.DeferredSignIn, accessor), accessor);
			return handler.Handle(new(Request(harness.UserId)), Cancellation).AsTask();
		}, responseAlreadyStarted: true, cookie);

		probe.Exception.ShouldBeNull();
		probe.IdentityKey.ShouldBe(StashedSignInKey);
		NextUrlOf(probe.Value.ShouldNotBeNull()).ShouldBe(harness.DeferredSignIn.BuildCompletionUrl(StashedSignInKey, "/"));
	}

	static ConfirmEmailChangeRequest Request(string userId, string? code = null) =>
		new() { UserId = userId, EmailInput = NewEmail, Code = code ?? _code };

	ValueTask<Outcome<NavigationResult>> HandleAsync(IPrincipalAccessor principal, string? code = null)
	{
		DefaultHttpContext context = new();
		context.Request.PathBase = "/base";
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(context);
		ConfirmEmailChangeHandler handler = new(_userManager, _signInManager, principal,
			new(Substitute.For<IDeferredSignIn>(), accessor), accessor);
		return handler.Handle(new(Request(_user.Id.ToString(), code)), Cancellation);
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
