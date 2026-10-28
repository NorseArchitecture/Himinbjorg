using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.SignInMethods;

namespace Norse.Identity.Web.Server.Tests.SignInMethods;

/// <summary>
///     <see cref="GetSignInMethodsHandler" /> authors every link between the sign-in pages over a stock
///     <see cref="SignInManager{TUser}" /> and a real scheme provider: each link carries only the landing
///     <see cref="ReturnUrls.Resolve" /> decided, PathBase-qualified, and only displayed schemes become provider links.
/// </summary>
public sealed class GetSignInMethodsHandlerTests : IDisposable
{
	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly AuthenticationOptions _schemes = new();

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Theory]
	[InlineData("/Account/Manage", "", "%2FAccount%2FManage")]
	[InlineData("https://evil.test/", "", "%2F")]
	[InlineData("", "", "%2F")]
	[InlineData("/app/Account/Manage", "/app", "%2Fapp%2FAccount%2FManage")]
	[InlineData("/app/../outside", "/app", "%2Fapp%2F")]
	async Task Every_url_carries_only_the_resolved_landing(string returnUrl, string pathBase, string landing)
	{
		AddScheme("Example", "Example Co");

		var response = await HandleAsync(returnUrl, pathBase);

		response.PasswordSignInUrl.ShouldBe($"{pathBase}/Account/Login?returnUrl={landing}");
		response.PasskeySignInUrl.ShouldBe($"{pathBase}/Account/LoginWithPasskey?returnUrl={landing}");
		response.Providers.ShouldHaveSingleItem().StartUrl
			.ShouldBe($"{pathBase}/Account/PerformExternalLogin?provider=Example&returnUrl={landing}");
	}

	[Fact]
	async Task Each_displayed_scheme_is_a_provider_link_and_hidden_schemes_are_not()
	{
		AddScheme("Zeta", "Zeta Login");
		AddScheme("Hidden", null);
		AddScheme("Alpha", "Alpha Login");

		var response = await HandleAsync("/", "");

		response.Providers.ShouldBe(
		[
			new ExternalProviderLink
			{
				DisplayName = "Alpha Login", StartUrl = "/Account/PerformExternalLogin?provider=Alpha&returnUrl=%2F"
			},
			new ExternalProviderLink
			{
				DisplayName = "Zeta Login", StartUrl = "/Account/PerformExternalLogin?provider=Zeta&returnUrl=%2F"
			}
		]);
	}

	[Fact]
	async Task No_schemes_answers_an_empty_array()
	{
		var response = await HandleAsync("/", "");

		response.Providers.ShouldBeEmpty();
	}

	public void Dispose() =>
		_userManager.Dispose();

	void AddScheme(string name, string? displayName) =>
		_schemes.AddScheme(name, scheme =>
		{
			scheme.HandlerType = typeof(IAuthenticationHandler);
			scheme.DisplayName = displayName;
		});

	async Task<SignInMethodsResponse> HandleAsync(string returnUrl, string pathBase)
	{
		DefaultHttpContext context = new();
		context.Request.PathBase = pathBase;
		HttpContextAccessor accessor = new() { HttpContext = context };
		SignInManager<NorseUser> signInManager = new(_userManager, accessor,
			Substitute.For<IUserClaimsPrincipalFactory<NorseUser>>(), Options.Create(new IdentityOptions()),
			NullLogger<SignInManager<NorseUser>>.Instance, new AuthenticationSchemeProvider(Options.Create(_schemes)),
			Substitute.For<IUserConfirmation<NorseUser>>());
		GetSignInMethodsHandler handler = new(signInManager, accessor);

		var outcome = await handler.Handle(
			new GetSignInMethodsCommand(new GetSignInMethodsRequest { ReturnUrl = returnUrl }), Cancellation);

		return BaseRequest.ValueOf(outcome);
	}
}
