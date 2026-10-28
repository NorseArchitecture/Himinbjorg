using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests.Account;

public sealed class RemoveExternalLoginHandlerTests
{
	const string Provider = "Google";
	const string ProviderKey = "google-subject";

	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly SignInManager<NorseUser> _signInManager = MockSignInManager.Create();
	readonly NorseUser _user = new() { UserName = "user@example.com", Email = "user@example.com" };

	public RemoveExternalLoginHandlerTests()
	{
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user);
		_userManager.RemoveLoginAsync(_user, Provider, ProviderKey).Returns(IdentityResult.Success);
	}

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Success_refreshes_the_sign_in_and_answers_the_status_url()
	{
		NextUrlOf(await HandleAsync())
			.ShouldBe("/base/Account/Manage/ExternalLogins?status=external-login-removed");
		await _userManager.Received(1).RemoveLoginAsync(_user, Provider, ProviderKey);
		await _signInManager.Received(1).RefreshSignInAsync(_user);
	}

	[Fact]
	async Task A_last_sign_in_method_refusal_answers_Conflict_and_refreshes_nothing()
	{
		_userManager.RemoveLoginAsync(_user, Provider, ProviderKey)
			.Returns(IdentityResult.Failed(new IdentityError
			{
				Code = NorseIdentityErrorCodes.LastSignInMethod,
				Description = "You cannot remove your only sign-in method."
			}));

		ProblemOf(await HandleAsync()).Category.ShouldBe(ErrorCategory.Conflict);
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
		await _userManager.DidNotReceiveWithAnyArgs().RemoveLoginAsync(default!, default!, default!);
		await _signInManager.DidNotReceiveWithAnyArgs().RefreshSignInAsync(default!);
	}

	ValueTask<Outcome<NavigationResult>> HandleAsync()
	{
		DefaultHttpContext context = new();
		context.Request.PathBase = "/base";
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(context);
		RemoveExternalLoginHandler handler = new(new AccountCaller(FakePrincipal.For(_user.Id), _userManager),
			_userManager, _signInManager, new(Substitute.For<IDeferredSignIn>(), accessor), accessor);
		return handler.Handle(new(new() { LoginProvider = Provider, ProviderKey = ProviderKey }), Cancellation);
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
