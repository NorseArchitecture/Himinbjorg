using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Components.Authorization;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using IAuthenticationService = Microsoft.AspNetCore.Authentication.IAuthenticationService;

namespace Norse.Identity.Web.Server.Tests.Account;

/// <summary>
///     The link-external-login pair over a real minimal pipeline: a slim host whose test middleware stands the
///     principal in before routing, the <see cref="AuthNPolicies.Account" /> policy on the manage group, a fake log
///     provider, and substitutes for the managers and the authentication service (whose forbid answers 403).
/// </summary>
public sealed class LinkExternalLoginEndpointTests : IAsyncDisposable
{
	const string Provider = "Google";
	const string ProviderKey = "google-subject";
	const string StartPath = "/Account/Manage/LinkExternalLogin?provider=Google";
	const string CallbackPath = "/Account/Manage/LinkExternalLoginCallback";
	const string NotAddedUrl = "/Account/Manage/ExternalLogins?status=external-login-not-added";

	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly SignInManager<NorseUser> _signInManager = MockSignInManager.Create();
	readonly IAuthenticationService _authentication = Substitute.For<IAuthenticationService>();
	readonly FakeLoggerProvider _logs = new();
	readonly IdentityErrorDescriber _describer = new();
	readonly NorseUser _user = new() { UserName = "user@example.com", Email = "user@example.com" };
	ClaimsPrincipal _principal;
	WebApplication? _app;

	public LinkExternalLoginEndpointTests()
	{
		_principal = new(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, _user.Id.ToString())], "Test"));
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user);
		_userManager.AddLoginAsync(_user, Arg.Any<UserLoginInfo>()).Returns(IdentityResult.Success);
		_signInManager.UserManager.GetUserId(Arg.Any<ClaimsPrincipal>())
			.Returns(call => call.Arg<ClaimsPrincipal>().FindFirstValue(ClaimTypes.NameIdentifier));
		_signInManager.GetExternalAuthenticationSchemesAsync()
			.Returns([new AuthenticationScheme(Provider, Provider, typeof(IAuthenticationHandler))]);
		_signInManager.ConfigureExternalAuthenticationProperties(Arg.Any<string>(), Arg.Any<string>(), Arg.Any<string>())
			.Returns(new AuthenticationProperties());
		_signInManager.GetExternalLoginInfoAsync(_user.Id.ToString())
			.Returns(new ExternalLoginInfo(_principal, Provider, ProviderKey, Provider));
		_authentication
			.When(service => service.ForbidAsync(Arg.Any<HttpContext>(), Arg.Any<string?>(),
				Arg.Any<AuthenticationProperties?>()))
			.Do(call => call.Arg<HttpContext>().Response.StatusCode = StatusCodes.Status403Forbidden);
	}

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task The_link_start_is_a_GET_that_challenges_the_named_provider()
	{
		using var client = await StartAsync();

		using var response = await client.GetAsync(new Uri(StartPath, UriKind.Relative), Cancellation);

		response.StatusCode.ShouldBe(HttpStatusCode.OK);
		_signInManager.Received(1).ConfigureExternalAuthenticationProperties(Provider,
			Arg.Is<string>(url => url.EndsWith(CallbackPath, StringComparison.Ordinal)), Arg.Is(_user.Id.ToString()));
		await _authentication.Received(1)
			.ChallengeAsync(Arg.Any<HttpContext>(), Provider, Arg.Any<AuthenticationProperties?>());
	}

	[Fact]
	async Task An_unknown_provider_redirects_with_the_not_added_key_and_challenges_nothing()
	{
		using var client = await StartAsync();

		using var response = await client.GetAsync(new Uri("/Account/Manage/LinkExternalLogin?provider=Cookies",
			UriKind.Relative), Cancellation);

		RedirectOf(response).ShouldBe(NotAddedUrl);
		_signInManager.DidNotReceiveWithAnyArgs().ConfigureExternalAuthenticationProperties(default, default, default);
		await _authentication.DidNotReceiveWithAnyArgs().ChallengeAsync(default!, default, default);
	}

	[Fact]
	async Task No_POST_link_start_remains()
	{
		using var client = await StartAsync();
		using FormUrlEncodedContent form = new([new("provider", Provider)]);

		using var response = await client.PostAsync(new Uri("/Account/Manage/LinkExternalLogin", UriKind.Relative), form,
			Cancellation);

		response.StatusCode.ShouldBeOneOf(HttpStatusCode.MethodNotAllowed, HttpStatusCode.NotFound);
		_signInManager.DidNotReceiveWithAnyArgs().ConfigureExternalAuthenticationProperties(default, default, default);
	}

	[Fact]
	async Task The_callback_adds_the_login_and_redirects_with_the_added_key()
	{
		using var client = await StartAsync();

		using var response = await GetCallbackAsync(client);

		RedirectOf(response).ShouldBe("/Account/Manage/ExternalLogins?status=external-login-added");
		await _userManager.Received(1).AddLoginAsync(_user,
			Arg.Is<UserLoginInfo>(login => login.LoginProvider == Provider && login.ProviderKey == ProviderKey));
		await AssertExternalCookieClearedAsync();
	}

	[Fact]
	async Task A_login_already_associated_redirects_with_the_not_added_key()
	{
		_userManager.AddLoginAsync(_user, Arg.Any<UserLoginInfo>())
			.Returns(IdentityResult.Failed(_describer.LoginAlreadyAssociated()));
		using var client = await StartAsync();

		using var response = await GetCallbackAsync(client);

		RedirectOf(response).ShouldBe(NotAddedUrl);
		await AssertExternalCookieClearedAsync();
		var logged = LinkLogs().ShouldHaveSingleItem();
		logged.Level.ShouldBe(LogLevel.Warning);
		logged.Message.ShouldContain(nameof(ErrorCategory.Conflict));
		logged.Message.ShouldNotContain(ProviderKey);
	}

	[Fact]
	async Task An_indeterminate_link_redirects_without_a_status_key()
	{
		_userManager.AddLoginAsync(_user, Arg.Any<UserLoginInfo>())
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));
		using var client = await StartAsync();

		using var response = await GetCallbackAsync(client);

		RedirectOf(response).ShouldBe("/Account/Manage/ExternalLogins");
		await AssertExternalCookieClearedAsync();
		LinkLogs().ShouldHaveSingleItem().Message.ShouldContain(nameof(ErrorCategory.Indeterminate));
	}

	[Fact]
	async Task A_missing_external_cookie_redirects_with_the_not_added_key()
	{
		_signInManager.GetExternalLoginInfoAsync(Arg.Any<string?>()).Returns((ExternalLoginInfo?)null);
		using var client = await StartAsync();

		using var response = await GetCallbackAsync(client);

		RedirectOf(response).ShouldBe(NotAddedUrl);
		await _userManager.DidNotReceiveWithAnyArgs().AddLoginAsync(default!, default!);
		await AssertExternalCookieClearedAsync();
	}

	[Theory]
	[InlineData(true)]
	[InlineData(false)]
	async Task A_callback_whose_caller_cannot_be_loaded_redirects_with_the_not_added_key(bool erased)
	{
		if (erased)
			_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>())
				.ThrowsAsync(new KeyDestroyedException(new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch)));
		else
			_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns((NorseUser?)null);
		using var client = await StartAsync();

		using var response = await GetCallbackAsync(client);

		RedirectOf(response).ShouldBe(NotAddedUrl);
		await _signInManager.DidNotReceiveWithAnyArgs().GetExternalLoginInfoAsync(default);
		await AssertExternalCookieClearedAsync();
		LinkLogs().ShouldHaveSingleItem().Message
			.ShouldContain(erased ? nameof(ErrorCategory.Erased) : nameof(ErrorCategory.NotFound));
	}

	[Theory]
	[InlineData(StartPath)]
	[InlineData(CallbackPath)]
	async Task The_manage_group_requires_the_account_policy(string path)
	{
		_principal = new(new ClaimsIdentity(
			[new Claim(ClaimTypes.NameIdentifier, _user.Id.ToString()), new Claim(ClaimTypes.Role, NorseRoles.Anonymous)],
			"Test"));
		using var client = await StartAsync();

		using var response = await client.GetAsync(new Uri(path, UriKind.Relative), Cancellation);

		response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
		_signInManager.DidNotReceiveWithAnyArgs().ConfigureExternalAuthenticationProperties(default, default, default);
		await _signInManager.DidNotReceiveWithAnyArgs().GetExternalLoginInfoAsync(default);
	}

	public async ValueTask DisposeAsync()
	{
		_userManager.Dispose();
		_logs.Dispose();
		if (_app is not null)
			await _app.DisposeAsync();
	}

	async Task<HttpClient> StartAsync()
	{
		var builder = WebApplication.CreateSlimBuilder();
		builder.WebHost.UseTestServer();
		builder.Logging
			.ClearProviders()
			.AddProvider(_logs);
		builder.Services
			.AddRouting()
			.AddSingleton(_userManager)
			.AddSingleton(_signInManager)
			.AddSingleton(_authentication)
			.AddAuthorization(options => options.AddPolicy(AuthNPolicies.Account, AuthNPolicies.ConfigureAccount));

		_app = builder.Build();
		_app.Use((context, next) =>
		{
			context.User = _principal;
			return next(context);
		});
		_app.UseRouting();
		_app.UseAuthorization();
		_app.MapAdditionalIdentityEndpoints();
		await _app.StartAsync(Cancellation);
		return _app.GetTestClient();
	}

	/// <summary>The records the link endpoints logged, without the host's own.</summary>
	FakeLogRecord[] LinkLogs() =>
		[
			.. _logs.Collector.GetSnapshot()
				.Where(record => record.Category == typeof(IdentityComponentsEndpointRouteBuilderExtensions).FullName)
		];

	Task AssertExternalCookieClearedAsync() =>
		_authentication.Received(1)
			.SignOutAsync(Arg.Any<HttpContext>(), IdentityConstants.ExternalScheme, Arg.Any<AuthenticationProperties?>());

	static Task<HttpResponseMessage> GetCallbackAsync(HttpClient client) =>
		client.GetAsync(new Uri(CallbackPath, UriKind.Relative), Cancellation);

	static string RedirectOf(HttpResponseMessage response)
	{
		response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
		return response.Headers.Location.ShouldNotBeNull().OriginalString;
	}
}
