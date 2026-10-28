using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests.Account;

public sealed class GetExternalLoginsHandlerTests
{
	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly SignInManager<NorseUser> _signInManager = MockSignInManager.Create();
	readonly NorseUser _user = new() { UserName = "user@example.com", Email = "user@example.com" };

	public GetExternalLoginsHandlerTests()
	{
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user);
		_signInManager.GetExternalAuthenticationSchemesAsync().Returns([Scheme("Google"), Scheme("Microsoft")]);
	}

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Lists_linked_logins_and_the_providers_not_yet_linked()
	{
		_userManager.GetLoginsAsync(_user).Returns([new("Google", "google-subject", "Google Account")]);

		var response = ResponseOf(await HandleAsync());

		response.Logins.ShouldBe([
			new ExternalLoginEntry { LoginProvider = "Google", ProviderKey = "google-subject", DisplayName = "Google Account" }
		]);
		response.AvailableProviders.ShouldBe([new ExternalProviderEntry { Name = "Microsoft", DisplayName = "Microsoft Account" }]);
	}

	[Theory]
	[InlineData(true, 1, true)]
	[InlineData(false, 2, true)]
	[InlineData(false, 1, false)]
	async Task Can_remove_when_a_password_exists_or_more_than_one_login(bool hasPassword, int loginCount, bool canRemove)
	{
		_userManager.HasPasswordAsync(_user).Returns(hasPassword);
		_userManager.GetLoginsAsync(_user)
			.Returns([.. Enumerable.Range(0, loginCount).Select(i => new UserLoginInfo($"Provider{i}", $"key-{i}", null))]);

		ResponseOf(await HandleAsync()).CanRemove.ShouldBe(canRemove);
	}

	static AuthenticationScheme Scheme(string name) =>
		new(name, $"{name} Account", typeof(IAuthenticationHandler));

	ValueTask<Outcome<ExternalLoginsResponse>> HandleAsync()
	{
		GetExternalLoginsHandler handler = new(_userManager, _signInManager, FakePrincipal.For(_user.Id));
		return handler.Handle(new(Unit.Value), Cancellation);
	}

	static ExternalLoginsResponse ResponseOf(Outcome<ExternalLoginsResponse> outcome)
	{
		outcome.TryGetValue(out Success<ExternalLoginsResponse> success).ShouldBeTrue();
		return success.Value;
	}
}
