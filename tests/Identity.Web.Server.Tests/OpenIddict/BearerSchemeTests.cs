using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Reflection;
using System.Runtime.Serialization;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApplicationParts;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Norse.Abstractions.Components.Authorization;
using Norse.Abstractions.Web.Server.Facade;
using Norse.Identity.Web.Server.OpenIddict;
using Norse.Infrastructure.Web.Server.Authentication;
using OpenIddict.Abstractions;
using OpenIddict.Validation;
using ProtoBuf.Grpc;
using ProtoBuf.Grpc.Configuration;
using ProtoBuf.Grpc.Server;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     <c>Norse.Bearer</c>, the bearer source Midgard's two lanes authenticate by name (spec §7.1), over the production
///     composition and Midgard's real <c>AddNorseAuthentication()</c>: a machine token reaches a façade controller through
///     <c>Norse.Machine</c>'s stamping (the positive Himinbjorg#49 fact), and every refusal that reaches
///     <c>Norse.Bearer</c>'s challenge is a bare 401, whether the bearer was authenticated first in the request (the
///     façade) or never (the gRPC lane with no bearer header, which challenges through <c>Norse.Machine</c>). A 403 on
///     any of these is the #49 regression.
/// </summary>
[Collection(PostgresTestGroup.Name)]
public sealed class BearerSchemeTests(PostgresIdentityFixture fixture)
{
	[Fact]
	async Task Norse_bearer_is_registered()
	{
		var builder = Host.CreateEmptyApplicationBuilder(new());
		builder.Configuration["ConnectionStrings:test"] = "Host=localhost;Database=norse_identity_test";
		using var certificate = IdentityTestCertificate.CreateFresh();
		builder.AddNorseAuthenticationService("test", certificate);
		builder.Services.AddNorseAuthentication();
		await using var services = builder.Services.BuildServiceProvider();

		ServiceCollectionExtensions.BearerScheme.ShouldBe(NorseSchemes.Bearer);
		var scheme = await services.GetRequiredService<IAuthenticationSchemeProvider>().GetSchemeAsync(NorseSchemes.Bearer);
		scheme.ShouldNotBeNull().HandlerType.ShouldBe(typeof(BearerChallengeHandler));
		// Midgard's BearerSchemeValidation: the host composing both realms passes the startup check.
		Should.NotThrow(() => services.GetRequiredService<IOptions<AuthenticationOptions>>().Value);
	}

	[Fact]
	async Task Validation_accepts_both_audiences()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await BearerHost.StartAsync(fixture);

		host.Services.GetRequiredService<IOptionsMonitor<OpenIddictValidationOptions>>().CurrentValue.Audiences
			.ShouldBe([NorseAudiences.Facade, NorseAudiences.User], ignoreOrder: true);
	}

	[Fact]
	async Task A_machine_token_authenticates_through_norse_machine()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await BearerHost.StartAsync(fixture);
		var (token, applicationId) = await host.MintMachineTokenAsync(TestContext.Current.CancellationToken);

		using var response = await host.GetFacadeAsync(token, TestContext.Current.CancellationToken);

		response.StatusCode.ShouldBe(HttpStatusCode.OK);
		var echo = await response.Content.ReadFromJsonAsync<LaneEcho>(TestContext.Current.CancellationToken);
		echo.ShouldNotBeNull();
		// The lane is Midgard's stamp, the identity's authentication type: OpenIddict's own type never survives.
		echo.AuthenticationType.ShouldBe(NorseLanes.Machine);
		echo.IdentityCount.ShouldBe(1);
		echo.Audiences.ShouldBe([NorseAudiences.Facade]);
		echo.NameIdentifier.ShouldBe(applicationId.ToString());
		host.FacadeInvocations.ShouldBe(1);
	}

	[Fact]
	async Task An_expired_token_challenges_with_a_bare_401()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await BearerHost.StartAsync(fixture, expiredTokens: true);
		var (token, _) = await host.MintMachineTokenAsync(TestContext.Current.CancellationToken);

		using var response = await host.GetFacadeAsync(token, TestContext.Current.CancellationToken);

		await ShouldBeBare401Async(response);
		// The rejection is the expiry, not any other reason a 401 could come from, and the header names the error alone: no
		// error_description, no error_uri naming OpenIddict (spec §5.7, Task 4.7).
		ShouldChallengeWithErrorAlone(response, "invalid_token");
		host.FacadeInvocations.ShouldBe(0);
	}

	// The Authorization header is the only bearer channel (OAuth 2.1 forbids query-string tokens): a valid token in
	// ?access_token= authenticates nothing on the cold gRPC path, so the challenge is the missing-token 401, never the
	// insufficient_access 403 an authenticated-then-challenged request would get.
	[Fact]
	async Task A_query_string_token_on_the_grpc_lane_challenges_with_a_bare_401()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await BearerHost.StartAsync(fixture);
		var (token, _) = await host.MintMachineTokenAsync(TestContext.Current.CancellationToken);

		using var response = await host.CallGrpcAsync(cookie: null, TestContext.Current.CancellationToken, query: token);

		await ShouldBeBare401Async(response);
	}

	[Fact]
	async Task A_query_string_token_on_the_facade_challenges_with_a_bare_401()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await BearerHost.StartAsync(fixture);
		var (token, _) = await host.MintMachineTokenAsync(TestContext.Current.CancellationToken);

		using var response = await host.GetFacadeAsync(null, TestContext.Current.CancellationToken, query: token);

		await ShouldBeBare401Async(response);
		host.FacadeInvocations.ShouldBe(0);
	}

	[Fact]
	async Task A_form_body_token_on_the_facade_challenges_with_a_bare_401()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await BearerHost.StartAsync(fixture);
		var (token, _) = await host.MintMachineTokenAsync(TestContext.Current.CancellationToken);

		using var response = await host.PostFacadeFormAsync(token, TestContext.Current.CancellationToken);

		await ShouldBeBare401Async(response);
		host.FacadeInvocations.ShouldBe(0);
	}

	[Fact]
	async Task A_missing_token_challenges_with_a_bare_401()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await BearerHost.StartAsync(fixture);

		using var response = await host.GetFacadeAsync(null, TestContext.Current.CancellationToken);

		await ShouldBeBare401Async(response);
		host.FacadeInvocations.ShouldBe(0);
	}

	// The cold path: the gRPC lane with no bearer header never authenticates Norse.Bearer, and challenges through
	// Norse.Machine -> Norse.Bearer (Midgard dropped its authenticate-before-challenge workaround in Task 2.2).
	[Fact]
	async Task A_credentialless_grpc_call_challenges_with_a_bare_401()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await BearerHost.StartAsync(fixture);

		using var response = await host.CallGrpcAsync(cookie: null, TestContext.Current.CancellationToken);

		await ShouldBeBare401Async(response);
		response.Headers.Contains(HeaderNames.SetCookie).ShouldBeFalse();
	}

	// The same cold path through the cookie branch: a present but invalid identity cookie is deleted and falls through
	// to no result, so the challenge again goes Norse.Machine -> Norse.Bearer with nothing authenticated.
	[Fact]
	async Task A_grpc_call_with_an_invalid_identity_cookie_challenges_with_a_bare_401()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await BearerHost.StartAsync(fixture);

		using var response = await host.CallGrpcAsync(cookie: "Norse.Identity=not-a-ticket", TestContext.Current.CancellationToken);

		await ShouldBeBare401Async(response);
	}

	// Buvy's lane ruling: a bearer on the gRPC lane selects Norse.User, and a machine token (aud Norse.Facade) fails the
	// lane's authentication there although Norse.Bearer itself validated it. The challenge that follows is still the bare
	// 401: the challenge's authenticate-first step finds a valid token, so this pins that OpenIddict's challenge then
	// answers no insufficient_access 403 (and no description or URI either).
	[Fact]
	async Task A_machine_token_on_the_grpc_lane_challenges_with_a_bare_401()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await BearerHost.StartAsync(fixture);
		var (token, _) = await host.MintMachineTokenAsync(TestContext.Current.CancellationToken);

		using var response = await host.CallGrpcAsync(cookie: null, TestContext.Current.CancellationToken, token);

		await ShouldBeBare401Async(response);
		var header = response.Headers.WwwAuthenticate.ShouldHaveSingleItem();
		header.Scheme.ShouldBe("Bearer");
		header.Parameter.ShouldBeOneOf([null, "error=\"invalid_token\""], "at most the bare error, never a description or a URI");
	}

	/// <summary>The one <c>WWW-Authenticate</c> header is <c>Bearer error="..."</c>, and nothing else.</summary>
	static void ShouldChallengeWithErrorAlone(HttpResponseMessage response, string error)
	{
		var header = response.Headers.WwwAuthenticate.ShouldHaveSingleItem();
		header.Scheme.ShouldBe("Bearer");
		header.Parameter.ShouldBe($"error=\"{error}\"");
	}

	static async Task ShouldBeBare401Async(HttpResponseMessage response)
	{
		response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
		response.Headers.Location.ShouldBeNull();
		(await response.Content.ReadAsByteArrayAsync(TestContext.Current.CancellationToken)).ShouldBeEmpty();
	}

	static class HeaderNames
	{
		public const string SetCookie = "Set-Cookie";
	}

	/// <summary>What the façade probe saw of its caller.</summary>
	/// <param name="AuthenticationType">The principal's primary identity's authentication type: the stamped lane.</param>
	/// <param name="IdentityCount">How many identities the principal holds.</param>
	/// <param name="Audiences">Every <c>aud</c> claim.</param>
	/// <param name="NameIdentifier">The <see cref="ClaimTypes.NameIdentifier" /> claim.</param>
	sealed record LaneEcho(
		[property: JsonPropertyName("authenticationType")] string? AuthenticationType,
		[property: JsonPropertyName("identityCount")] int IdentityCount,
		[property: JsonPropertyName("audiences")] string[] Audiences,
		[property: JsonPropertyName("nameIdentifier")] string? NameIdentifier);

	/// <summary>
	///     A second <see cref="TestServer" /> host on the fixture's database: the fixture's production composition, then
	///     Midgard's lanes (<c>AddNorseAuthentication()</c>, after <c>AddIdentity</c> as the composition root requires), the
	///     machine policy, one façade controller and one code-first gRPC service under it, and the token endpoint.
	/// </summary>
	sealed class BearerHost : IAsyncDisposable
	{
		readonly WebApplication _app;
		readonly X509Certificate2 _certificate;
		readonly HttpClient _client;
		readonly InvocationCounter _invocations;

		BearerHost(WebApplication app, X509Certificate2 certificate, InvocationCounter invocations)
		{
			_app = app;
			_certificate = certificate;
			_invocations = invocations;
			_client = app.GetTestServer().CreateClient();
			// OpenIddict refuses plain HTTP; TestServer never opens a socket, so an https base address is enough.
			_client.BaseAddress = new("https://localhost/");
		}

		public IServiceProvider Services => _app.Services;

		public int FacadeInvocations => _invocations.Count;

		/// <summary>Starts a host on <paramref name="fixture" />'s database.</summary>
		/// <param name="fixture">The provider's fixture, already available.</param>
		/// <param name="expiredTokens">
		///     Mint one-minute access tokens and run validation's clock ten minutes ahead, so a token is already expired
		///     when it is presented. The issuer keeps the real clock, and the gap stays inside the test certificate's
		///     validity, which validation also checks against its clock.
		/// </param>
		public static async Task<BearerHost> StartAsync(IdentityFixture fixture, bool expiredTokens = false)
		{
			var certificate = IdentityTestCertificate.CreateFresh();
			InvocationCounter invocations = new();
			var builder = fixture.Compose(certificate);
			builder.Services.AddSingleton(invocations);
			builder.Services.AddNorseAuthentication();
			builder.Services.AddAuthorizationBuilder()
				.AddPolicy(NorsePolicies.Machine, NorsePlatformPolicies.Machine);
			if (expiredTokens)
				builder.Services.AddOpenIddict()
					.AddServer(static server => server.SetAccessTokenLifetime(TimeSpan.FromMinutes(1)))
					.AddValidation(static validation => validation.Configure(static options =>
						options.TimeProvider = new FakeTimeProvider(DateTimeOffset.UtcNow.AddMinutes(10))));
			builder.Services.AddControllers()
				.ConfigureApplicationPartManager(static manager =>
				{
					manager.ApplicationParts.Clear();
					manager.ApplicationParts.Add(new OneControllerPart());
					manager.FeatureProviders.Add(new OneControllerFeature());
				});
			builder.Services.AddCodeFirstGrpc();

			var app = builder.Build();
			app.UseRouting();
			app.UseAuthentication();
			app.UseAuthorization();
			app.MapNorseOpenIddictEndpoints();
			app.MapControllers();
			app.MapGrpcService<MachineProbeService>();
			await app.StartAsync(CancellationToken.None);
			return new(app, certificate, invocations);
		}

		/// <summary>Seeds a fresh confidential client and mints its client-credentials access token.</summary>
		/// <param name="cancellationToken">The cancellation token.</param>
		public async Task<(string Token, Guid ApplicationId)> MintMachineTokenAsync(CancellationToken cancellationToken)
		{
			var clientId = $"bearer-{Guid.NewGuid():N}";
			const string Secret = "bearer-secret-value";
			await using (var scope = _app.Services.CreateAsyncScope())
			{
				var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
				var application = await manager.CreateAsync(new OpenIddictApplicationDescriptor
				{
					ClientId = clientId,
					ClientSecret = Secret,
					ClientType = OpenIddictConstants.ClientTypes.Confidential,
					Permissions =
					{
						OpenIddictConstants.Permissions.Endpoints.Token,
						OpenIddictConstants.Permissions.GrantTypes.ClientCredentials
					}
				}, cancellationToken);
				var id = await manager.GetIdAsync(application, cancellationToken) ??
					throw new InvalidOperationException("The seeded application carries no id.");

				using FormUrlEncodedContent content = new(new Dictionary<string, string>
				{
					[OpenIddictConstants.Parameters.GrantType] = OpenIddictConstants.GrantTypes.ClientCredentials,
					[OpenIddictConstants.Parameters.ClientId] = clientId,
					[OpenIddictConstants.Parameters.ClientSecret] = Secret
				});
				using var response = await _client.PostAsync(new Uri("/connect/token", UriKind.Relative), content, cancellationToken);
				if (!response.IsSuccessStatusCode)
					throw new InvalidOperationException(
						$"The token endpoint answered {response.StatusCode}: {await response.Content.ReadAsStringAsync(cancellationToken)}");
				var payload = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken) ??
					throw new InvalidOperationException("The token endpoint answered no body.");
				return (payload.AccessToken, Guid.Parse(id));
			}
		}

		/// <summary>A GET to the façade probe, bearing <paramref name="token" /> when there is one.</summary>
		/// <param name="token">The access token, or none.</param>
		/// <param name="cancellationToken">The cancellation token.</param>
		/// <param name="query">An access token to carry as <c>?access_token=</c> instead, or none.</param>
		public async Task<HttpResponseMessage> GetFacadeAsync(string? token, CancellationToken cancellationToken, string? query = null)
		{
			using HttpRequestMessage request = new(HttpMethod.Get, new Uri(WithQueryToken("/bearer-probe", query), UriKind.Relative));
			if (token is not null)
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
			return await _client.SendAsync(request, cancellationToken);
		}

		/// <summary>A form POST to the façade probe carrying <paramref name="token" /> as the <c>access_token</c> form field.</summary>
		/// <param name="token">The access token.</param>
		/// <param name="cancellationToken">The cancellation token.</param>
		public async Task<HttpResponseMessage> PostFacadeFormAsync(string token, CancellationToken cancellationToken)
		{
			using FormUrlEncodedContent content = new(new Dictionary<string, string> { [OpenIddictConstants.Parameters.AccessToken] = token });
			return await _client.PostAsync(new Uri("/bearer-probe", UriKind.Relative), content, cancellationToken);
		}

		static string WithQueryToken(string path, string? token) =>
			token is null ? path : $"{path}?{OpenIddictConstants.Parameters.AccessToken}={Uri.EscapeDataString(token)}";

		/// <summary>A unary call to the gRPC probe, carrying <paramref name="cookie" /> and <paramref name="token" /> when there are any.</summary>
		/// <param name="cookie">A raw <c>Cookie</c> header value, or none.</param>
		/// <param name="cancellationToken">The cancellation token.</param>
		/// <param name="token">An access token to bear, or none.</param>
		/// <param name="query">An access token to carry as <c>?access_token=</c> instead, or none.</param>
		public async Task<HttpResponseMessage> CallGrpcAsync(string? cookie, CancellationToken cancellationToken, string? token = null,
			string? query = null)
		{
			// A well-formed, zero-length unary frame: enough for routing and authorization to run.
			using ByteArrayContent content = new([0, 0, 0, 0, 0]);
			content.Headers.ContentType = new MediaTypeHeaderValue("application/grpc");
			using HttpRequestMessage request = new(HttpMethod.Post, new Uri(WithQueryToken("/bearer.MachineProbe/Ping", query), UriKind.Relative))
			{
				Content = content,
				Version = HttpVersion.Version20,
				VersionPolicy = HttpVersionPolicy.RequestVersionExact
			};
			if (cookie is not null)
				request.Headers.Add("Cookie", cookie);
			if (token is not null)
				request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
			return await _client.SendAsync(request, cancellationToken);
		}

		public async ValueTask DisposeAsync()
		{
			_client.Dispose();
			// Stopped first, so the hosted services (the OpenIddict pruner) end as a host stop ends them, not faulted by disposal.
			await _app.StopAsync(CancellationToken.None);
			await _app.DisposeAsync();
			_certificate.Dispose();
		}

		sealed record TokenResponse([property: JsonPropertyName("access_token")] string AccessToken);
	}

	/// <summary>How many times the façade probe's action ran: a refusal must happen before it.</summary>
	sealed class InvocationCounter
	{
		int _count;

		public int Count => _count;

		public void Increment() =>
			Interlocked.Increment(ref _count);
	}

	/// <summary>
	///     Exposes exactly the façade probe: the default part manager would scan this whole test assembly, and the default
	///     feature provider only recognizes public controllers.
	/// </summary>
	sealed class OneControllerPart : ApplicationPart, IApplicationPartTypeProvider
	{
		public override string Name => nameof(FacadeProbeController);

		public IEnumerable<TypeInfo> Types { get; } = [typeof(FacadeProbeController).GetTypeInfo()];
	}

	sealed class OneControllerFeature : ControllerFeatureProvider
	{
		protected override bool IsController(TypeInfo typeInfo) =>
			typeInfo.AsType() == typeof(FacadeProbeController);
	}

	/// <summary>A façade controller: <see cref="GrpcControllerBase" /> carries the machine policy, and the lane selector routes it to <c>Norse.Machine</c>.</summary>
	[Route("bearer-probe")]
	sealed class FacadeProbeController(InvocationCounter invocations) : GrpcControllerBase
	{
		// POST too, so a form-body token has an action to reach.
		[HttpGet]
		[HttpPost]
		public ActionResult<LaneEcho> Get()
		{
			invocations.Increment();
			return Ok(new LaneEcho(
				User.Identity?.AuthenticationType,
				User.Identities.Count(),
				[.. User.FindAll(OpenIddictConstants.Claims.Audience).Select(static claim => claim.Value)],
				User.FindFirstValue(ClaimTypes.NameIdentifier)));
		}
	}

	// PBN2008: the analyzer cannot verify a unary CallContext method shape here (the same false positive Midgard's
	// LaneHost suppresses); the call never reaches the method anyway, refused at authorization.
	[Service("bearer.MachineProbe")]
#pragma warning disable PBN2008
	interface IMachineProbeService
	{
		Task<Pong> PingAsync(Ping request, CallContext context = default);
	}
#pragma warning restore PBN2008

	/// <summary>A code-first gRPC service under the machine policy, so a credential-less call is challenged.</summary>
	[Authorize(Policy = NorsePolicies.Machine)]
	sealed class MachineProbeService : IMachineProbeService
	{
		public Task<Pong> PingAsync(Ping request, CallContext context = default) =>
			Task.FromResult(new Pong());
	}

	[DataContract]
	sealed class Ping
	{
		[DataMember(Order = 1)] public string Value { get; set; } = string.Empty;
	}

	[DataContract]
	sealed class Pong
	{
		[DataMember(Order = 1)] public string Value { get; set; } = string.Empty;
	}
}
