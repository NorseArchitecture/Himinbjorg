using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.TwoFactor;

namespace Norse.Identity.Web.Server.Tests.TwoFactor;

/// <summary>
///     <see cref="ForgetTwoFactorClientHandler" />: forgets the calling machine and answers the two-factor page with
///     <c>browser-forgotten</c>. On a circuit the remember-machine cookie's delete is stashed, so the answer rides the
///     deferred completion that performs it.
/// </summary>
public sealed class ForgetTwoFactorClientHandlerTests
{
	const string RememberKey = "remember-key";
	const string StatusUrl = "/base/Account/Manage/TwoFactorAuthentication?status=browser-forgotten";
	const string CompletionUrl = "/base/_auth/complete?key=remember-key";

	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly SignInManager<NorseUser> _signInManager = MockSignInManager.Create();
	readonly IDeferredSignIn _deferredSignIn = Substitute.For<IDeferredSignIn>();
	readonly IHttpContextAccessor _accessor = BaseRequest.Accessor();
	readonly NorseUser _user = new() { Id = Guid.CreateVersion7(), UserName = "user@example.com", Email = "user@example.com" };

	public ForgetTwoFactorClientHandlerTests()
	{
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user);
		_deferredSignIn.BuildCompletionUrl(RememberKey, StatusUrl).Returns(CompletionUrl);
	}

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Forget_answers_the_status_url_through_the_deferral()
	{
		// What NorseSignInManager does on a circuit: stash the cookie delete and park its key.
		_signInManager.When(static manager => manager.ForgetTwoFactorClientAsync())
			.Do(_ => _accessor.HttpContext!.Items[NorseSignInManager.DeferredRememberClientKeyItemName] = RememberKey);

		BaseRequest.ValueOf(await HandleAsync()).NextUrl.ShouldBe(CompletionUrl);
		await _signInManager.Received(1).ForgetTwoFactorClientAsync();
	}

	[Fact]
	async Task Forget_without_a_stash_answers_the_status_url()
	{
		BaseRequest.ValueOf(await HandleAsync()).NextUrl.ShouldBe(StatusUrl);
		await _signInManager.Received(1).ForgetTwoFactorClientAsync();
	}

	[Fact]
	async Task An_erased_subject_answers_Erased()
	{
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).ThrowsAsync(new KeyDestroyedException(receipt));

		var problem = BaseRequest.ProblemOf(await HandleAsync());

		problem.Category.ShouldBe(ErrorCategory.Erased);
		problem.Receipt.ShouldBeSameAs(receipt);
		await _signInManager.DidNotReceive().ForgetTwoFactorClientAsync();
	}

	ValueTask<Outcome<NavigationResult>> HandleAsync()
	{
		ForgetTwoFactorClientHandler handler = new(new AccountCaller(FakePrincipal.For(_user.Id), _userManager),
			_signInManager, new(_deferredSignIn, _accessor), _accessor);
		return handler.Handle(new(Unit.Value), Cancellation);
	}
}
