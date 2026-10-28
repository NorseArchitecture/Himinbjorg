using System.Net;
using System.Text;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests.ExternalLogin;

/// <summary>
///     The external-login GET start over a real pipeline: the stock <see cref="SignInManager{TUser}" /> composition,
///     the identity cookies, the fake remote scheme registered through <c>AddRemoteScheme</c> with the shared failure
///     handler, and a cookie jar driven by hand (the test server follows no redirect). It proceeds only for
///     <c>Sec-Fetch-Site: same-origin</c> or <c>none</c> (T3-34); every refusal returns to login with the resolved
///     landing and challenges nothing.
/// </summary>
public sealed class ExternalLoginStartEndpointTests : IAsyncDisposable
{
	const string Landing = "/Account/Manage";
	const string LoginWithLanding = "/Account/Login?ReturnUrl=%2FAccount%2FManage";

	const string Start = $"/Account/PerformExternalLogin?provider={FakeRemote.Scheme}&returnUrl=%2FAccount%2FManage";

	WebApplication? _app;

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task A_same_origin_start_challenges_the_provider_with_the_resolved_landing()
	{
		using var client = await StartAsync();

		using var response = await GetAsync(client, Start, "same-origin");

		var properties = ChallengedProperties(response);
		properties.Items["LoginProvider"].ShouldBe(FakeRemote.Scheme);
		var redirect = properties.RedirectUri.ShouldNotBeNull();
		redirect.ShouldStartWith("/Account/ExternalLogin?");
		var query = QueryHelpers.ParseQuery(redirect[redirect.IndexOf('?', StringComparison.Ordinal)..]);
		query["Action"].ToString().ShouldBe("LoginCallback");
		query["ReturnUrl"].ToString().ShouldBe(Landing);
		CookiesOf(response).ShouldContain(cookie => cookie.StartsWith(".AspNetCore.Correlation.", StringComparison.Ordinal));
	}

	[Fact]
	async Task A_typed_url_start_challenges()
	{
		using var client = await StartAsync();

		using var response = await GetAsync(client, Start, "none");

		ChallengedProperties(response).Items["LoginProvider"].ShouldBe(FakeRemote.Scheme);
	}

	[Fact]
	async Task A_configured_oidc_scheme_challenges_to_the_authorization_endpoint_with_state_and_nonce()
	{
		using DiscoveryStub discovery = new();
		using var client = await StartAsync(
			static (auth, configuration) => auth.AddNorseExternalProviders(configuration),
			new()
			{
				["Identity:ExternalProviders:Example:DisplayName"] = "Example Co",
				["Identity:ExternalProviders:Example:Authority"] = "https://provider.test",
				["Identity:ExternalProviders:Example:ClientId"] = "norse-client"
			},
			services => services.Configure<OpenIdConnectOptions>("Example", o => o.BackchannelHttpHandler = discovery));

		using var response = await GetAsync(client, "/Account/PerformExternalLogin?provider=Example&returnUrl=%2F",
			"same-origin");

		response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
		var location = response.Headers.Location.ShouldNotBeNull();
		location.GetLeftPart(UriPartial.Path).ShouldBe("https://provider.test/authorize");
		var query = QueryHelpers.ParseQuery(location.Query);
		query["client_id"].ToString().ShouldBe("norse-client");
		query["response_type"].ToString().ShouldBe("code");
		query["code_challenge_method"].ToString().ShouldBe("S256");
		query["code_challenge"].ToString().ShouldNotBeNullOrEmpty();
		query["state"].ToString().ShouldNotBeNullOrEmpty();
		query["nonce"].ToString().ShouldNotBeNullOrEmpty();
		query["redirect_uri"].ToString().ShouldEndWith("/signin-example");
		var cookies = CookiesOf(response);
		cookies.ShouldContain(cookie => cookie.StartsWith(".AspNetCore.Correlation.", StringComparison.Ordinal));
		cookies.ShouldContain(cookie => cookie.StartsWith(".AspNetCore.OpenIdConnect.Nonce.", StringComparison.Ordinal));
	}

	[Fact]
	async Task A_cross_site_start_challenges_nothing() =>
		await AssertRefusedAsync("cross-site");

	[Fact]
	async Task A_same_site_start_challenges_nothing() =>
		await AssertRefusedAsync("same-site");

	[Fact]
	async Task A_start_without_fetch_metadata_challenges_nothing() =>
		await AssertRefusedAsync(null);

	[Fact]
	async Task A_foreign_return_url_starts_with_the_app_root_landing()
	{
		using var client = await StartAsync();

		using var response = await GetAsync(client,
			$"/Account/PerformExternalLogin?provider={FakeRemote.Scheme}&returnUrl=https%3A%2F%2Fevil.test%2F", "same-origin");

		var redirect = ChallengedProperties(response).RedirectUri.ShouldNotBeNull();
		QueryHelpers.ParseQuery(redirect[redirect.IndexOf('?', StringComparison.Ordinal)..])["ReturnUrl"].ToString()
			.ShouldBe("/");
	}

	[Theory]
	[InlineData("Nope")]
	[InlineData("Identity.External")]
	async Task An_unknown_provider_returns_to_login_and_challenges_nothing(string provider)
	{
		using var client = await StartAsync();

		using var response = await GetAsync(client,
			$"/Account/PerformExternalLogin?provider={provider}&returnUrl=%2FAccount%2FManage", "same-origin");

		AssertReturnedToLogin(response);
	}

	[Fact]
	async Task The_start_needs_no_antiforgery_token()
	{
		using var client = await StartAsync();

		var start = _app!.Services.GetRequiredService<EndpointDataSource>().Endpoints
			.OfType<RouteEndpoint>()
			.Single(endpoint => endpoint.RoutePattern.RawText == "/Account/PerformExternalLogin");
		start.Metadata.GetMetadata<IAntiforgeryMetadata>().ShouldBeNull();
		using var response = await GetAsync(client, Start, "same-origin");

		ChallengedProperties(response).Items["LoginProvider"].ShouldBe(FakeRemote.Scheme);
	}

	[Theory]
	[InlineData("POST", "/Account/PerformExternalLogin")]
	[InlineData("POST", "/Account/Logout")]
	[InlineData("GET", "/Account/PasskeyCreationOptions")]
	[InlineData("POST", "/Account/PasskeyCreationOptions")]
	[InlineData("GET", "/Account/PasskeyRequestOptions")]
	[InlineData("POST", "/Account/PasskeyRequestOptions")]
	async Task No_post_start_logout_or_passkey_endpoint_remains(string method, string path)
	{
		using var client = await StartAsync();
		using HttpRequestMessage request = new(new HttpMethod(method), new Uri(path, UriKind.Relative));
		request.Headers.Add("Sec-Fetch-Site", "same-origin");
		if (method == "POST")
			request.Content = new FormUrlEncodedContent([new("provider", FakeRemote.Scheme), new("returnUrl", "/")]);

		using var response = await client.SendAsync(request, Cancellation);

		response.StatusCode.ShouldBeOneOf(HttpStatusCode.NotFound, HttpStatusCode.MethodNotAllowed);
		CookiesOf(response).ShouldBeEmpty();
	}

	public async ValueTask DisposeAsync()
	{
		if (_app is not null)
			await _app.DisposeAsync();
	}

	async Task AssertRefusedAsync(string? fetchSite)
	{
		using var client = await StartAsync();

		using var response = await GetAsync(client, Start, fetchSite);

		AssertReturnedToLogin(response);
	}

	static void AssertReturnedToLogin(HttpResponseMessage response)
	{
		response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
		response.Headers.Location.ShouldNotBeNull().OriginalString.ShouldBe(LoginWithLanding);
		CookiesOf(response).ShouldBeEmpty();
	}

	async Task<HttpClient> StartAsync(Action<AuthenticationBuilder, IConfiguration>? providers = null,
		Dictionary<string, string?>? settings = null, Action<IServiceCollection>? configure = null)
	{
		var builder = WebApplication.CreateSlimBuilder();
		builder.WebHost.UseTestServer();
		builder.Logging.ClearProviders();
		builder.Configuration.AddInMemoryCollection(settings ?? []);
		builder.Services
			.AddRouting()
			.AddAntiforgery()
			.AddAuthorization(options => options.AddPolicy(AuthNPolicies.Account, AuthNPolicies.ConfigureAccount))
			.AddSingleton(Substitute.For<IUserStore<NorseUser>>())
			.AddDataProtection().UseEphemeralDataProtectionProvider();
		builder.Services.AddIdentityCore<NorseUser>().AddSignInManager();
		var authentication = builder.Services.AddAuthentication(IdentityConstants.ApplicationScheme);
		authentication.AddIdentityCookies();
		(providers ?? (static (auth, _) => auth.AddFakeRemote()))(authentication, builder.Configuration);
		configure?.Invoke(builder.Services);

		_app = builder.Build();
		_app.UseRouting();
		_app.UseAuthentication();
		_app.UseAuthorization();
		_app.UseAntiforgery();
		_app.MapNorseExternalLoginEndpoints();
		_app.MapFakeProvider();
		await _app.StartAsync(Cancellation);
		return _app.GetTestClient();
	}

	static async Task<HttpResponseMessage> GetAsync(HttpClient client, string path, string? fetchSite)
	{
		using HttpRequestMessage request = new(HttpMethod.Get, new Uri(path, UriKind.Relative));
		if (fetchSite is not null)
			request.Headers.Add("Sec-Fetch-Site", fetchSite);
		return await client.SendAsync(request, Cancellation);
	}

	/// <summary>The properties the fake scheme challenged with, read back from its <c>state</c>.</summary>
	AuthenticationProperties ChallengedProperties(HttpResponseMessage response)
	{
		response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
		var location = response.Headers.Location.ShouldNotBeNull().OriginalString;
		location.ShouldStartWith(FakeRemote.AuthorizePath + "?state=");
		var state = QueryHelpers.ParseQuery(location[location.IndexOf('?', StringComparison.Ordinal)..])["state"];
		return FakeRemote.StateFormat(_app!.Services.GetRequiredService<IDataProtectionProvider>())
			.Unprotect(state).ShouldNotBeNull();
	}

	static string[] CookiesOf(HttpResponseMessage response) =>
		response.Headers.TryGetValues("Set-Cookie", out var cookies) ?
			[.. cookies] :
			[];

	/// <summary>A static discovery document and empty key set for <c>https://provider.test</c>; no network.</summary>
	sealed class DiscoveryStub : HttpMessageHandler
	{
		const string Discovery = """
			{
			  "issuer": "https://provider.test",
			  "authorization_endpoint": "https://provider.test/authorize",
			  "token_endpoint": "https://provider.test/token",
			  "jwks_uri": "https://provider.test/jwks",
			  "response_types_supported": ["code"],
			  "subject_types_supported": ["public"],
			  "id_token_signing_alg_values_supported": ["RS256"],
			  "code_challenge_methods_supported": ["S256"]
			}
			""";

		protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
			CancellationToken cancellationToken)
		{
			var body = request.RequestUri!.AbsolutePath switch
			{
				"/.well-known/openid-configuration" => Discovery,
				"/jwks" => """{ "keys": [] }""",
				_ => null
			};
			return Task.FromResult(body is null ?
				new HttpResponseMessage(HttpStatusCode.NotFound) :
				new HttpResponseMessage(HttpStatusCode.OK)
				{
					Content = new StringContent(body, Encoding.UTF8, "application/json")
				});
		}
	}
}
