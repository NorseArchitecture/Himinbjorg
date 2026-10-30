using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore; // GetOpenIddictServerRequest lives here, not in OpenIddict.Server.AspNetCore.
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.JsonWebTokens;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.OpenIddict;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     The production authorize endpoint on a fixture's database (Train 4 ruling PF2): the fixture's production
///     composition and <c>MapNorseOpenIddictEndpoints</c>, a controllable clock, a real <see cref="IHttpContextAccessor" />
///     (the fixture's is a fixed context), the named <see cref="PausePoints" /> (inert until armed), and one test-only
///     sign-in endpoint standing in for <c>LoginHandler</c>: a real password sign-in through
///     <see cref="NorseSignInManager" /> with its landing parked exactly as the handler parks it.
///     Since Task 4.5 there is no stand-in: the token endpoint, the grant boundary and the production
///     <see cref="GrantTermination" /> run as composed, and a fact that injects a failure replaces the termination itself.
/// </summary>
/// <remarks>
///     A cookie is the request header value the browser would send, <c>name=value</c> pairs for every identity-cookie
///     chunk the sign-in wrote; nothing follows redirects, so each fact reads every hop itself.
/// </remarks>
sealed class AuthorizeHost : IAsyncDisposable
{
	/// <summary>The first-party public client every fact authorizes for: implicit consent, two redirect URIs.</summary>
	public const string ClientId = "authorize-native";

	/// <summary>A second first-party public client, for a marker presented by another client.</summary>
	public const string OtherClientId = "authorize-native-other";

	/// <summary>A public client whose consent type is explicit, which this server has no page for.</summary>
	public const string ExplicitConsentClientId = "authorize-explicit";

	/// <summary>Every seeded user's password.</summary>
	public const string Password = "Correct-Horse-1!";

	/// <summary>The token endpoint, below <c>PathBase</c>.</summary>
	public const string TokenPath = "/connect/token";

	/// <summary>The revocation endpoint, below <c>PathBase</c>.</summary>
	public const string RevocationPath = "/connect/revoke";

	/// <summary>The test-only sign-in endpoint, below <c>PathBase</c>.</summary>
	const string SignInPath = "/test/sign-in";

	/// <summary>The clients' first redirect URI.</summary>
	public static readonly Uri RedirectUri = new("http://127.0.0.1/cb");

	/// <summary><see cref="ClientId" />'s second redirect URI.</summary>
	public static readonly Uri OtherRedirectUri = new("http://127.0.0.1/cb2");

	readonly WebApplication _app;
	readonly X509Certificate2 _certificate;
	readonly HttpClient _client;
	readonly ConcurrentQueue<string?> _passedMarkers;
	readonly ConcurrentQueue<Exception> _failures;

	AuthorizeHost(WebApplication app, X509Certificate2 certificate, FakeTimeProvider clock, PathString pathBase,
		ConcurrentQueue<string?> passedMarkers, PausePoints pauses, ConcurrentQueue<Exception> failures)
	{
		_app = app;
		_certificate = certificate;
		Clock = clock;
		PathBase = pathBase;
		_passedMarkers = passedMarkers;
		Pauses = pauses;
		_failures = failures;
		_client = app.GetTestServer().CreateClient();
		// OpenIddict refuses plain HTTP; TestServer never opens a socket, so an https base address is enough.
		_client.BaseAddress = new("https://localhost/");
	}

	/// <summary>The server's clock: OpenIddict's, the marker's, the ledger's and the stamp point's.</summary>
	public FakeTimeProvider Clock { get; }

	/// <summary>The <c>PathBase</c> the host is mounted under; empty at the root.</summary>
	public PathString PathBase { get; }

	/// <summary>
	///     The <c>norse_reauth</c> value each request the production authorize endpoint was handed carried, in OpenIddict's
	///     own request parameters, read by an endpoint filter immediately before the endpoint runs.
	/// </summary>
	public IReadOnlyList<string?> PassedMarkers => [.. _passedMarkers];

	/// <summary>The application's services, for facts that read the marker protector or the ledger.</summary>
	public IServiceProvider Services => _app.Services;

	/// <summary>The named points a token or revocation request can be held at.</summary>
	public PausePoints Pauses { get; }

	/// <summary>
	///     Every exception a request let escape, answered as the bare HTTP 500 a host's exception handler would send; empty
	///     unless the host was started with <c>answerFailuresAs500</c>.
	/// </summary>
	public IReadOnlyList<Exception> Failures => [.. _failures];

	/// <summary>Starts a host on <paramref name="fixture" />'s database.</summary>
	/// <param name="fixture">The provider's fixture, already available.</param>
	/// <param name="pathBase">The <c>PathBase</c> to mount the host under.</param>
	/// <param name="configure">More composition on top, before the host is built.</param>
	/// <param name="map">More endpoints, mapped after the production ones.</param>
	/// <param name="answerFailuresAs500">
	///     Catch an exception a request lets escape, record it in <see cref="Failures" /> and answer a bare 500, as a
	///     production host's exception handler does; otherwise the exception reaches the test client.
	/// </param>
	public static async Task<AuthorizeHost> StartAsync(IdentityFixture fixture, PathString pathBase = default,
		Action<WebApplicationBuilder>? configure = null, Action<WebApplication>? map = null, bool answerFailuresAs500 = false)
	{
		var certificate = IdentityTestCertificate.CreateFresh();
		FakeTimeProvider clock = new(DateTimeOffset.UtcNow);
		ConcurrentQueue<string?> passedMarkers = new();
		PausePoints pauses = new();
		ConcurrentQueue<Exception> failures = new();

		var builder = fixture.Compose(certificate);
		builder.Services
			.Replace(ServiceDescriptor.Singleton<TimeProvider>(clock))
			.Replace(ServiceDescriptor.Singleton<IHttpContextAccessor, HttpContextAccessor>())
			.AddOpenIddict()
			.AddServer(server =>
			{
				pauses.Register(server);
				server.Configure(options => options.TimeProvider = clock);
			});
		configure?.Invoke(builder);

		var app = builder.Build();
		if (answerFailuresAs500)
			app.Use(async (context, next) =>
			{
				try
				{
					await next(context);
				}
				catch (Exception exception) when (!context.Response.HasStarted)
				{
					failures.Enqueue(exception);
					context.Response.Clear();
					context.Response.StatusCode = StatusCodes.Status500InternalServerError;
				}
			});
		if (pathBase.HasValue)
			app.UsePathBase(pathBase);
		app.UseRouting();
		app.UseAuthentication();
		app.UseAuthorization();
		app.MapNorseOpenIddictEndpoints().AddEndpointFilter(async (context, next) =>
		{
			if (context.HttpContext.Request.Path.StartsWithSegments(ReauthMarkers.AuthorizePath, StringComparison.Ordinal))
				passedMarkers.Enqueue((string?)context.HttpContext.GetOpenIddictServerRequest()?.GetParameter("norse_reauth"));
			return await next(context);
		});
		app.MapGet(SignInPath, SignInEndpointAsync);
		map?.Invoke(app);
		await app.StartAsync(CancellationToken.None);
		await RegisterClientsAsync(app);
		return new(app, certificate, clock, pathBase, passedMarkers, pauses, failures);
	}

	/// <summary>A user with <see cref="Password" />, through the real managers.</summary>
	/// <param name="fixture">The fixture whose database the host runs on.</param>
	public static async Task<NorseUser> SeedUserAsync(IdentityFixture fixture)
	{
		var seeded = await fixture.SeedUserAsync($"authorize-{Guid.NewGuid():N}@example.com");
		var userManager = fixture.CreateUserManager();
		(await userManager.AddPasswordAsync((await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull(),
			Password)).Succeeded.ShouldBeTrue();
		return seeded;
	}

	/// <summary>
	///     A password login for <paramref name="user" /> through the real <c>LoginHandler</c>, as the login page's gRPC hop
	///     sends it (failures counted toward a lockout), on a request of its own.
	/// </summary>
	/// <param name="user">The user.</param>
	/// <param name="password">The password tried.</param>
	public async Task<Outcome<NavigationResult>> LoginAsync(NorseUser user, string password)
	{
		await using var scope = _app.Services.CreateAsyncScope();
		var accessor = scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>();
		accessor.HttpContext = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
		try
		{
			return await scope.ServiceProvider.GetRequiredService<IRequestHandler<LoginCommand, NavigationResult>>()
				.Handle(new(new LoginRequest { EmailInput = user.Email!, Password = password }),
					TestContext.Current.CancellationToken);
		}
		finally
		{
			accessor.HttpContext = null;
		}
	}

	/// <summary>
	///     Locks <paramref name="user" /> out the way anyone knowing the email can: wrong passwords through the real login
	///     handler until Identity's failure threshold is reached. Fails the fact unless the user is then locked out.
	/// </summary>
	/// <param name="user">The user.</param>
	public async Task LockOutByFailedPasswordsAsync(NorseUser user)
	{
		var attempts = _app.Services.GetRequiredService<IOptions<IdentityOptions>>().Value.Lockout.MaxFailedAccessAttempts;
		for (var attempt = 1; attempt <= attempts; attempt++)
			(await LoginAsync(user, "Wrong-Horse-9!")).TryGetValue(out Failed _).ShouldBeTrue($"wrong password {attempt} is refused");

		await using var scope = _app.Services.CreateAsyncScope();
		var userManager = scope.ServiceProvider.GetRequiredService<UserManager<NorseUser>>();
		(await userManager.IsLockedOutAsync((await userManager.FindByIdAsync(user.Id.ToString())).ShouldNotBeNull()))
			.ShouldBeTrue("the failed passwords locked the user out");
	}

	/// <summary>
	///     A password sign-in for <paramref name="user" /> landing on <paramref name="returnUrl" />, as the login page's
	///     handler runs it: answers the identity cookie the browser would then hold.
	/// </summary>
	/// <param name="user">The user.</param>
	/// <param name="returnUrl">The <c>returnUrl</c> the login page was reached with; none lands on the app root.</param>
	public async Task<string> SignInAsync(NorseUser user, string? returnUrl = null)
	{
		KeyValuePair<string, string?>[] parameters = [new("user", user.Id.ToString()), new("returnUrl", returnUrl ?? string.Empty)];
		var query = QueryString.Create(parameters);
		using var response = await SendAsync(HttpMethod.Get, PathBase + SignInPath + query, cookie: null);
		response.StatusCode.ShouldBe(HttpStatusCode.OK, "the test sign-in succeeded");
		return IdentityCookie(response).ShouldNotBeNull("the sign-in wrote the identity cookie");
	}

	/// <summary>Sends <paramref name="request" /> to the authorize endpoint, as a GET query or a POSTed form.</summary>
	/// <param name="request">The authorize parameters.</param>
	/// <param name="cookie">The identity cookie to present, if any.</param>
	/// <param name="post">POST the parameters as a form instead.</param>
	public async Task<HttpResponseMessage> AuthorizeAsync(AuthorizeRequest request, string? cookie = null, bool post = false)
	{
		if (!post)
			return await SendAsync(HttpMethod.Get, request.Url(PathBase), cookie);

		using FormUrlEncodedContent form = new(request.Pairs);
		return await SendAsync(HttpMethod.Post, PathBase + ReauthMarkers.AuthorizePath, cookie, form);
	}

	/// <summary>Sends a GET to a local URL, as a browser following a redirect does.</summary>
	/// <param name="url">The URL, root-relative (any <c>PathBase</c> included).</param>
	/// <param name="cookie">The identity cookie to present, if any.</param>
	public Task<HttpResponseMessage> GetAsync(string url, string? cookie = null) =>
		SendAsync(HttpMethod.Get, url, cookie);

	/// <summary>Sends <paramref name="request" /> as it is, for a fact that shapes its own request (a gRPC frame, say).</summary>
	/// <param name="request">The request, root-relative (any <c>PathBase</c> included).</param>
	public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request) =>
		_client.SendAsync(request, TestContext.Current.CancellationToken);

	/// <summary>
	///     The code the authorize endpoint issues for <paramref name="request" /> to <paramref name="cookie" />'s holder,
	///     read from the redirect to the client. Fails the fact unless a code was issued.
	/// </summary>
	/// <param name="request">The authorize request.</param>
	/// <param name="cookie">The identity cookie, fresh enough to need no re-authentication.</param>
	public async Task<string> IssueCodeAsync(AuthorizeRequest request, string cookie)
	{
		using var response = await AuthorizeAsync(request, cookie);
		var location = response.Headers.Location?.OriginalString;
		response.StatusCode.ShouldBe(HttpStatusCode.Redirect, location);
		location.ShouldNotBeNull().ShouldStartWith($"{request[Parameters.RedirectUri]}?");
		var code = QueryHelpers.ParseQuery(new Uri(location).Query)[Parameters.Code].ToString();
		code.ShouldNotBeNullOrEmpty($"the redirect carries a code: {location}");
		return code;
	}

	/// <summary>Redeems <paramref name="code" /> at the token endpoint as <paramref name="request" />'s client, with its verifier.</summary>
	/// <param name="code">The authorization code.</param>
	/// <param name="request">The authorize request the code was issued for.</param>
	public Task<HttpResponseMessage> RedeemAsync(string code, AuthorizeRequest request) =>
		PostTokenAsync([
			new(Parameters.GrantType, GrantTypes.AuthorizationCode),
			new(Parameters.Code, code),
			new(Parameters.RedirectUri, request[Parameters.RedirectUri]),
			new(Parameters.ClientId, request[Parameters.ClientId]),
			new(Parameters.CodeVerifier, request.Verifier)
		]);

	/// <summary>Refreshes with <paramref name="refreshToken" /> at the token endpoint.</summary>
	/// <param name="refreshToken">The refresh token.</param>
	/// <param name="clientId">The client presenting it.</param>
	public Task<HttpResponseMessage> RefreshAsync(string refreshToken, string clientId = ClientId) =>
		PostTokenAsync([
			new(Parameters.GrantType, GrantTypes.RefreshToken),
			new(Parameters.RefreshToken, refreshToken),
			new(Parameters.ClientId, clientId)
		]);

	/// <summary>Presents <paramref name="token" /> at the revocation endpoint as <paramref name="clientId" />.</summary>
	/// <param name="token">Any token.</param>
	/// <param name="clientId">The client presenting it.</param>
	/// <param name="clientSecret">The client's secret, posted beside its id, if any.</param>
	public Task<HttpResponseMessage> RevokeAsync(string token, string clientId = ClientId, string? clientSecret = null) =>
		PostFormAsync(RevocationPath, [
			new(Parameters.Token, token),
			new(Parameters.ClientId, clientId),
			.. clientSecret is null ? [] : (KeyValuePair<string, string>[])[new(Parameters.ClientSecret, clientSecret)]
		]);

	/// <summary>Posts <paramref name="parameters" /> to the token endpoint as a form.</summary>
	/// <param name="parameters">The token request's parameters.</param>
	public Task<HttpResponseMessage> PostTokenAsync(IEnumerable<KeyValuePair<string, string>> parameters) =>
		PostFormAsync(TokenPath, parameters);

	/// <summary>Posts <paramref name="parameters" /> as a form to <paramref name="path" />, below <c>PathBase</c>.</summary>
	/// <param name="path">The endpoint's path.</param>
	/// <param name="parameters">The request's parameters.</param>
	public async Task<HttpResponseMessage> PostFormAsync(string path, IEnumerable<KeyValuePair<string, string>> parameters)
	{
		using FormUrlEncodedContent form = new(parameters);
		return await SendAsync(HttpMethod.Post, PathBase + path, cookie: null, form);
	}

	/// <summary>Sets every token of <paramref name="authorizationId" /> to <paramref name="status" />, straight in the database.</summary>
	/// <param name="authorizationId">The authorization.</param>
	/// <param name="status">The status every one of its tokens takes.</param>
	public async Task SetTokenStatusAsync(Guid authorizationId, string status)
	{
		await using var scope = _app.Services.CreateAsyncScope();
		await scope.ServiceProvider.GetRequiredService<NorseIdentityDbContext>()
			.Set<NorseOpenIddictToken>()
			.Where(token => token.AuthorizationId == authorizationId)
			.ExecuteUpdateAsync(setters => setters.SetProperty(static token => token.Status, status));
	}

	/// <summary>The principal an identity cookie carries, unprotected by the scheme's own cookie manager and ticket format.</summary>
	/// <param name="cookie">The cookie, as a request header value.</param>
	public ClaimsPrincipal ReadCookie(string cookie)
	{
		var options = _app.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
			.Get(IdentityConstants.ApplicationScheme);
		DefaultHttpContext context = new();
		context.Request.Headers.Cookie = cookie;
		var value = options.CookieManager.GetRequestCookie(context, options.Cookie.Name!).ShouldNotBeNull();
		return options.TicketDataFormat.Unprotect(value).ShouldNotBeNull("the identity cookie unprotects").Principal;
	}

	/// <summary>
	///     Every claim <paramref name="token" /> carries. Codes and refresh tokens reach the client as reference identifiers
	///     (OpenIddict 8's default), so their payload is read back through the token manager, then decrypted through the
	///     server's own token handler and encryption keys; access and id tokens are read as they are.
	/// </summary>
	/// <param name="token">A token this server issued.</param>
	public async Task<ClaimsIdentity> UnprotectAsync(string token)
	{
		if (!token.Contains('.', StringComparison.Ordinal))
		{
			await using var scope = _app.Services.CreateAsyncScope();
			var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
			var entry = (await manager.FindByReferenceIdAsync(token)).ShouldNotBeNull("the reference token has an entry");
			token = (await manager.GetPayloadAsync(entry)).ShouldNotBeNull("the reference token's entry carries its payload");
		}

		var options = _app.Services.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;
		JsonWebToken read = new(token);
		var payload = read.IsEncrypted ?
			new JsonWebToken(options.JsonWebTokenHandler.DecryptToken(read, options.TokenValidationParameters)) :
			read;
		return new(payload.Claims);
	}

	/// <summary>The id of the entry behind <paramref name="token" />, as the token itself carries it.</summary>
	/// <param name="token">A code or refresh token this server issued.</param>
	public async Task<Guid> TokenIdAsync(string token) =>
		Guid.Parse((await UnprotectAsync(token)).FindAll(Claims.Private.TokenId).ShouldHaveSingleItem().Value);

	/// <summary>Every token <paramref name="userId" />'s authorizations hold, by id, read straight from the database.</summary>
	/// <param name="userId">The user.</param>
	public async Task<IReadOnlyDictionary<Guid, TokenRow>> ReadTokensAsync(Guid userId)
	{
		await using var scope = _app.Services.CreateAsyncScope();
		var context = scope.ServiceProvider.GetRequiredService<NorseIdentityDbContext>();
		var subject = userId.ToString();
		return await context.Set<NorseOpenIddictToken>()
			.Where(token => token.Subject == subject)
			.Select(static token => new TokenRow(token.Id, token.AuthorizationId, token.Type, token.Status))
			.ToDictionaryAsync(static token => token.Id);
	}

	/// <summary>How many tokens name <paramref name="userId" /> as their subject, under any authorization or none.</summary>
	/// <param name="userId">The user.</param>
	public async Task<int> CountTokensAsync(Guid userId)
	{
		await using var scope = _app.Services.CreateAsyncScope();
		var subject = userId.ToString();
		return await scope.ServiceProvider.GetRequiredService<NorseIdentityDbContext>()
			.Set<NorseOpenIddictToken>()
			.CountAsync(token => token.Subject == subject);
	}

	/// <summary>Every authorization <paramref name="userId" /> holds, each with its tokens, read straight from the database.</summary>
	/// <param name="userId">The user.</param>
	public async Task<IReadOnlyList<GrantRow>> ReadGrantsAsync(Guid userId)
	{
		await using var scope = _app.Services.CreateAsyncScope();
		var context = scope.ServiceProvider.GetRequiredService<NorseIdentityDbContext>();
		var subject = userId.ToString();
		var authorizations = await context.Set<NorseOpenIddictAuthorization>()
			.Where(authorization => authorization.Subject == subject)
			.Select(static authorization =>
				new { authorization.Id, authorization.Type, authorization.Status, authorization.ApplicationId })
			.ToListAsync();
		Guid[] ids = [.. authorizations.Select(static authorization => authorization.Id)];
		var tokens = await context.Set<NorseOpenIddictToken>()
			.Where(token => token.AuthorizationId.HasValue && ids.Contains(token.AuthorizationId.Value))
			.Select(static token => new { AuthorizationId = token.AuthorizationId!.Value, token.Type, token.Status })
			.ToListAsync();
		return
		[
			.. authorizations.Select(authorization => new GrantRow(authorization.Id, authorization.Type,
				authorization.Status, authorization.ApplicationId,
				[.. tokens.Where(token => token.AuthorizationId == authorization.Id).Select(static token => token.Type)],
				[.. tokens.Where(token => token.AuthorizationId == authorization.Id).Select(static token => token.Status)]))
		];
	}

	/// <inheritdoc />
	public async ValueTask DisposeAsync()
	{
		Pauses.ReleaseAll();
		_client.Dispose();
		// Stopped first, so the hosted services (the OpenIddict pruner) end as a host stop ends them, not faulted by disposal.
		await _app.StopAsync(CancellationToken.None);
		await _app.DisposeAsync();
		_certificate.Dispose();
	}

	/// <summary>The identity cookie a response wrote, as a request header value, or <see langword="null" />.</summary>
	/// <param name="response">The response.</param>
	public static string? IdentityCookie(HttpResponseMessage response)
	{
		string[] pairs =
		[
			.. (response.Headers.TryGetValues("Set-Cookie", out var values) ? values : [])
				.Select(static header => header.Split(';', 2)[0])
				.Where(static pair => pair.StartsWith("Norse.Identity", StringComparison.Ordinal) && !pair.EndsWith('='))
		];
		return pairs.Length == 0 ?
			null :
			string.Join("; ", pairs);
	}

	async Task<HttpResponseMessage> SendAsync(HttpMethod method, string url, string? cookie, HttpContent? content = null)
	{
		using HttpRequestMessage request = new(method, new Uri(url, UriKind.Relative)) { Content = content };
		if (cookie is not null)
			request.Headers.Add("Cookie", cookie);
		return await _client.SendAsync(request, TestContext.Current.CancellationToken);
	}

	// LoginHandler's sign-in, minus the wire: the landing resolved through ReturnUrls and parked for the one call.
	static async Task<IResult> SignInEndpointAsync(HttpContext context, Guid user, string? returnUrl)
	{
		var signIn = (NorseSignInManager)context.RequestServices.GetRequiredService<SignInManager<NorseUser>>();
		var found = (await signIn.UserManager.FindByIdAsync(user.ToString())).ShouldNotBeNull();
		Microsoft.AspNetCore.Identity.SignInResult result;
		using (ParkedReturnUrl.Park(context, ReturnUrls.Resolve(returnUrl, context.Request.PathBase)))
			result = await signIn.PasswordSignInAsync(found, Password, isPersistent: false, lockoutOnFailure: false);
		return result.Succeeded ?
			Results.Ok() :
			Results.Unauthorized();
	}

	/// <summary>Registers the three clients once per database.</summary>
	static async Task RegisterClientsAsync(WebApplication app)
	{
		await using var scope = app.Services.CreateAsyncScope();
		var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
		await RegisterAsync(manager, ClientId, ConsentTypes.Implicit, RedirectUri, OtherRedirectUri);
		await RegisterAsync(manager, OtherClientId, ConsentTypes.Implicit, RedirectUri);
		await RegisterAsync(manager, ExplicitConsentClientId, ConsentTypes.Explicit, RedirectUri);
	}

	static async Task RegisterAsync(IOpenIddictApplicationManager manager, string clientId, string consentType,
		params Uri[] redirectUris)
	{
		if (await manager.FindByClientIdAsync(clientId) is not null)
			return;
		OpenIddictApplicationDescriptor descriptor = new()
		{
			ClientId = clientId,
			ClientType = ClientTypes.Public,
			ConsentType = consentType,
			Permissions =
			{
				Permissions.Endpoints.Authorization,
				Permissions.Endpoints.Token,
				Permissions.Endpoints.Revocation,
				Permissions.GrantTypes.AuthorizationCode,
				Permissions.GrantTypes.RefreshToken,
				Permissions.ResponseTypes.Code
			},
			Requirements = { Requirements.Features.ProofKeyForCodeExchange }
		};
		foreach (var redirectUri in redirectUris)
			descriptor.RedirectUris.Add(redirectUri);
		await manager.CreateAsync(descriptor);
	}

	/// <summary>One authorization and its tokens' types.</summary>
	/// <param name="Id">The authorization's id.</param>
	/// <param name="Type">Its type.</param>
	/// <param name="Status">Its status.</param>
	/// <param name="ApplicationId">The client it was created for.</param>
	/// <param name="TokenTypes">Its tokens' types.</param>
	/// <param name="TokenStatuses">Its tokens' statuses, in the same order.</param>
	public sealed record GrantRow(Guid Id, string? Type, string? Status, Guid? ApplicationId, IReadOnlyList<string?> TokenTypes,
		IReadOnlyList<string?> TokenStatuses);

	/// <summary>One token row.</summary>
	/// <param name="Id">The token's id.</param>
	/// <param name="AuthorizationId">The authorization it is linked to, if any.</param>
	/// <param name="Type">Its type.</param>
	/// <param name="Status">Its status.</param>
	public sealed record TokenRow(Guid Id, Guid? AuthorizationId, string? Type, string? Status);
}

/// <summary>
///     An authorize request's parameters, in order, repeats allowed: a well-formed code + PKCE (S256) request by default,
///     changed one parameter at a time.
/// </summary>
/// <param name="Pairs">The parameters, in the order they are sent.</param>
sealed record AuthorizeRequest(ImmutableList<KeyValuePair<string, string>> Pairs)
{
	/// <summary>The PKCE verifier <see cref="Create" /> derived the challenge from, for the code's redemption.</summary>
	public string Verifier { get; init; } = string.Empty;

	/// <summary>
	///     A request from <paramref name="clientId" /> for <c>openid offline_access</c>, with a fresh state, nonce and PKCE
	///     verifier.
	/// </summary>
	/// <param name="clientId">The client.</param>
	/// <param name="redirectUri">The redirect URI; <see cref="AuthorizeHost.RedirectUri" /> by default.</param>
	public static AuthorizeRequest Create(string clientId = AuthorizeHost.ClientId, Uri? redirectUri = null)
	{
		var verifier = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
		return new(
		[
			new(Parameters.ClientId, clientId),
			new(Parameters.RedirectUri, (redirectUri ?? AuthorizeHost.RedirectUri).AbsoluteUri),
			new(Parameters.ResponseType, ResponseTypes.Code),
			new(Parameters.Scope, $"{Scopes.OpenId} {Scopes.OfflineAccess}"),
			new(Parameters.State, Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16))),
			new(Parameters.Nonce, Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(16))),
			new(Parameters.CodeChallenge, Challenge(verifier)),
			new(Parameters.CodeChallengeMethod, CodeChallengeMethods.Sha256)
		])
		{
			Verifier = verifier
		};
	}

	/// <summary>The PKCE S256 challenge for <paramref name="verifier" />.</summary>
	/// <param name="verifier">The verifier.</param>
	public static string Challenge(string verifier) =>
		Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));

	/// <summary>The one value of <paramref name="name" />.</summary>
	/// <param name="name">The parameter.</param>
	public string this[string name] =>
		Pairs.Single(parameter => parameter.Key == name).Value;

	/// <summary>The same request with every <paramref name="name" /> replaced by one <paramref name="value" />, in place.</summary>
	/// <param name="name">The parameter.</param>
	/// <param name="value">Its one value.</param>
	public AuthorizeRequest With(string name, string value)
	{
		var index = Pairs.FindIndex(parameter => parameter.Key == name);
		return index < 0 ?
			Adding(name, value) :
			this with { Pairs = Without(name).Pairs.Insert(index, new(name, value)) };
	}

	/// <summary>The same request with one more <paramref name="name" /> = <paramref name="value" /> at the end.</summary>
	/// <param name="name">The parameter.</param>
	/// <param name="value">The value.</param>
	public AuthorizeRequest Adding(string name, string value) =>
		this with { Pairs = Pairs.Add(new(name, value)) };

	/// <summary>The same request without <paramref name="name" />.</summary>
	/// <param name="name">The parameter.</param>
	public AuthorizeRequest Without(string name) =>
		this with { Pairs = [.. Pairs.Where(parameter => parameter.Key != name)] };

	/// <summary>The GET form, under <paramref name="pathBase" />.</summary>
	/// <param name="pathBase">The host's <c>PathBase</c>.</param>
	public string Url(PathString pathBase) =>
		pathBase + ReauthMarkers.AuthorizePath +
		QueryString.Create(Pairs.Select(static parameter =>
			new KeyValuePair<string, StringValues>(parameter.Key, parameter.Value)));
}
