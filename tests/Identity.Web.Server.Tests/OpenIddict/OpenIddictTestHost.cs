using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore; // GetOpenIddictServerRequest lives here, not in OpenIddict.Server.AspNetCore.
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.OpenIddict;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     A second <see cref="TestServer" /> host on a fixture's database (Train 4 ruling PF2): the fixture's production
///     composition (which since Task 4.4 enables the code and refresh flows, PKCE, the scopes, zero reuse leeway, the
///     authorize and revocation endpoints and the grant boundary itself, so this host configures none of them again;
///     registering the boundary twice would run it twice, and a second endpoint URI would be a second spelling), over a
///     substitute <see cref="IGrantTermination" />, a controllable clock, named pause
///     points, and test-only passthrough authorize and token endpoints that sign in one fixed principal. It drives
///     OpenIddict's own pipeline, never Norse's endpoints, which the Phase 4 suites drive instead.
/// </summary>
/// <remarks>
///     The registered public client is <see cref="ClientId" /> with redirect <see cref="RedirectUri" />. Each host signs
///     in its own subject (<see cref="Subject" />), so a fact finds its grants by subject on the shared database.
/// </remarks>
sealed class OpenIddictTestHost : IAsyncDisposable
{
	/// <summary>The test-registered public client.</summary>
	public const string ClientId = "test-native";

	/// <summary>The client's one redirect URI.</summary>
	public static readonly Uri RedirectUri = new("http://127.0.0.1/cb");

	readonly WebApplication _app;
	readonly X509Certificate2 _certificate;
	readonly HttpClient _client;
	readonly PausePoints _pauses;
	readonly ConcurrentQueue<string> _journal;

	OpenIddictTestHost(WebApplication app, X509Certificate2 certificate, PausePoints pauses, ConcurrentQueue<string> journal,
		RecordingGrantTermination termination, FakeTimeProvider clock, string subject)
	{
		_app = app;
		_certificate = certificate;
		_pauses = pauses;
		_journal = journal;
		Termination = termination;
		Clock = clock;
		Subject = subject;
		_client = app.GetTestServer().CreateClient();
		// OpenIddict refuses plain HTTP; TestServer never opens a socket, so an https base address is enough.
		_client.BaseAddress = new("https://localhost/");
	}

	/// <summary>The stand-in the grant boundary ends grants through: it records each call and ends nothing.</summary>
	public RecordingGrantTermination Termination { get; }

	/// <summary>The server's clock.</summary>
	public FakeTimeProvider Clock { get; }

	/// <summary>The fixed subject this host's authorize endpoint signs in.</summary>
	public string Subject { get; }

	/// <summary>
	///     What the recording handlers saw, in order, as <c>{handler} {endpoint} {token type} {authorization id}</c>; empty
	///     unless the host was started with <c>recordValidation</c>.
	/// </summary>
	public IReadOnlyList<string> Journal => [.. _journal];

	/// <summary>The server's resolved handler list, in dispatch order.</summary>
	public IReadOnlyList<OpenIddictServerHandlerDescriptor> Handlers =>
		_app.Services.GetRequiredService<IOptions<OpenIddictServerOptions>>().Value.Handlers;

	/// <summary>Starts a host on <paramref name="fixture" />'s database.</summary>
	/// <param name="fixture">The provider's fixture, already available.</param>
	/// <param name="recordValidation">
	///     Replace <see cref="EndGrantOnReuse" /> and <c>ValidateTokenEntry</c> with recording wrappers that keep each
	///     one's own descriptor (order and filters) and delegate to a real instance, so <see cref="Journal" /> shows
	///     which ran, and in what order.
	/// </param>
	/// <param name="revokeOnEnd">
	///     Make the <see cref="IGrantTermination" /> stand-in run <c>EndGrant</c>'s step 1 for real
	///     (<see cref="GrantStatements.RevokeAuthorizationAsync" />), so a fact can observe a grant end's security
	///     consequence. Step 2 and the retries are the production <see cref="GrantTermination" />'s, which this stand-in replaces.
	/// </param>
	public static async Task<OpenIddictTestHost> StartAsync(IdentityFixture fixture, bool recordValidation = false,
		bool revokeOnEnd = false)
	{
		var certificate = IdentityTestCertificate.CreateFresh();
		RecordingGrantTermination termination = new();
		FakeTimeProvider clock = new(DateTimeOffset.UtcNow);
		PausePoints pauses = new();
		ConcurrentQueue<string> journal = new();

		var builder = fixture.Compose(certificate);
		builder.Services
			.AddSingleton<IGrantTermination>(termination)
			.AddOpenIddict()
			.AddServer(server =>
			{
				pauses.Register(server);
				server
					.Configure(options => options.TimeProvider = clock)
					.UseAspNetCore(aspNetCore => aspNetCore.EnableAuthorizationEndpointPassthrough());
				if (recordValidation)
					server
						.RemoveEventHandler(EndGrantOnReuse.Descriptor)
						.RemoveEventHandler(Protection.ValidateTokenEntry.Descriptor)
						.AddEventHandler(Recorded(EndGrantOnReuse.Descriptor,
							static services => ActivatorUtilities.CreateInstance<EndGrantOnReuse>(services), journal))
						.AddEventHandler(Recorded(Protection.ValidateTokenEntry.Descriptor,
							static _ => new Protection.ValidateTokenEntry(), journal));
			});

		var subject = $"premise-{Guid.NewGuid():N}";
		var app = builder.Build();
		if (revokeOnEnd)
			termination.RevokeThrough(app.Services.GetRequiredService<IServiceScopeFactory>());
		app.UseAuthentication();
		app.UseAuthorization();
		app.MapMethods("/connect/authorize", [HttpMethods.Get, HttpMethods.Post], (HttpContext context) => Authorize(context, subject));
		// Cast, so the endpoint writes the result: the method group alone would bind as a RequestDelegate.
		app.MapPost("/connect/token", (Delegate)Exchange);
		await app.StartAsync(CancellationToken.None);
		await RegisterClientAsync(app);
		return new(app, certificate, pauses, journal, termination, clock, subject);
	}

	/// <summary>Holds the next request that reaches <paramref name="point" /> until the returned pause is released.</summary>
	/// <param name="point">The point.</param>
	public Pause Arm(PausePoint point) =>
		_pauses.Arm(point);

	/// <summary>Forgets what the recording handlers saw so far.</summary>
	public void ClearJournal() =>
		_journal.Clear();

	/// <summary>
	///     An authorization request for <c>openid offline_access</c> with an S256 challenge, answered by the passthrough
	///     authorize endpoint: the code from the redirect, and its verifier.
	/// </summary>
	/// <param name="cancellationToken">The cancellation token.</param>
	public async Task<(string Code, string Verifier)> AuthorizeAsync(CancellationToken cancellationToken = default)
	{
		var verifier = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
		using var response = await RequestAuthorizationAsync(verifier, null, cancellationToken);
		var location = response.Headers.Location;
		if (response.StatusCode is not HttpStatusCode.Redirect || location is null)
			throw new InvalidOperationException(
				$"The authorize request answered {response.StatusCode}: {await response.Content.ReadAsStringAsync(cancellationToken)}");
		var parameters = QueryHelpers.ParseQuery(location.Query);
		return parameters.TryGetValue(Parameters.Code, out var code) && code.ToString() is { Length: > 0 } value ?
			(value, verifier) :
			throw new InvalidOperationException($"The authorize redirect carries no code: {location}");
	}

	/// <summary>The same authorization request carrying <paramref name="idTokenHint" />, answered as it is.</summary>
	/// <param name="idTokenHint">The <c>id_token_hint</c>.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	public Task<HttpResponseMessage> RequestAuthorizationAsync(string idTokenHint, CancellationToken cancellationToken = default) =>
		RequestAuthorizationAsync(Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32)), idTokenHint, cancellationToken);

	Task<HttpResponseMessage> RequestAuthorizationAsync(string verifier, string? idTokenHint, CancellationToken cancellationToken)
	{
		var challenge = Base64Url.EncodeToString(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
		Dictionary<string, string?> query = new()
		{
			[Parameters.ClientId] = ClientId,
			[Parameters.RedirectUri] = RedirectUri.AbsoluteUri,
			[Parameters.ResponseType] = ResponseTypes.Code,
			[Parameters.Scope] = $"{Scopes.OpenId} {Scopes.OfflineAccess}",
			[Parameters.CodeChallenge] = challenge,
			[Parameters.CodeChallengeMethod] = CodeChallengeMethods.Sha256
		};
		if (idTokenHint is not null)
			query[Parameters.IdTokenHint] = idTokenHint;
		return _client.GetAsync(new Uri(QueryHelpers.AddQueryString("/connect/authorize", query), UriKind.Relative),
			cancellationToken);
	}

	/// <summary>Redeems <paramref name="code" /> at the token endpoint.</summary>
	/// <param name="code">The authorization code.</param>
	/// <param name="verifier">Its PKCE verifier.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	public Task<HttpResponseMessage> RedeemCodeAsync(string code, string verifier, CancellationToken cancellationToken = default) =>
		PostAsync("/connect/token", new()
		{
			[Parameters.GrantType] = GrantTypes.AuthorizationCode,
			[Parameters.Code] = code,
			[Parameters.RedirectUri] = RedirectUri.AbsoluteUri,
			[Parameters.ClientId] = ClientId,
			[Parameters.CodeVerifier] = verifier
		}, cancellationToken);

	/// <summary>Refreshes with <paramref name="refreshToken" /> at the token endpoint.</summary>
	/// <param name="refreshToken">The refresh token.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	public Task<HttpResponseMessage> RefreshAsync(string refreshToken, CancellationToken cancellationToken = default) =>
		PostAsync("/connect/token", new()
		{
			[Parameters.GrantType] = GrantTypes.RefreshToken,
			[Parameters.RefreshToken] = refreshToken,
			[Parameters.ClientId] = ClientId
		}, cancellationToken);

	/// <summary>Presents <paramref name="token" /> at the revocation endpoint.</summary>
	/// <param name="token">Any token.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	public Task<HttpResponseMessage> RevokeAsync(string token, CancellationToken cancellationToken = default) =>
		PostAsync("/connect/revoke", new()
		{
			[Parameters.Token] = token,
			[Parameters.ClientId] = ClientId
		}, cancellationToken);

	/// <summary>A whole sign-in: authorize, then redeem the code. Throws unless the exchange succeeded.</summary>
	/// <param name="cancellationToken">The cancellation token.</param>
	public async Task<TokenSet> SignInAsync(CancellationToken cancellationToken = default)
	{
		var (code, verifier) = await AuthorizeAsync(cancellationToken);
		using var response = await RedeemCodeAsync(code, verifier, cancellationToken);
		return await ReadTokensAsync(response, cancellationToken);
	}

	/// <summary>The tokens a successful token response carries. Throws, with the body, otherwise.</summary>
	/// <param name="response">The token endpoint's response.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	public static async Task<TokenSet> ReadTokensAsync(HttpResponseMessage response, CancellationToken cancellationToken = default)
	{
		if (!response.IsSuccessStatusCode)
			throw new InvalidOperationException(
				$"The token endpoint answered {response.StatusCode}: {await response.Content.ReadAsStringAsync(cancellationToken)}");
		return await response.Content.ReadFromJsonAsync<TokenSet>(cancellationToken) ??
			throw new InvalidOperationException("The token endpoint answered no body.");
	}

	/// <summary>Every authorization this host's subject holds, each with its tokens, read straight from the database.</summary>
	/// <param name="cancellationToken">The cancellation token.</param>
	public async Task<IReadOnlyList<GrantRow>> ReadGrantsAsync(CancellationToken cancellationToken = default)
	{
		await using var scope = _app.Services.CreateAsyncScope();
		var context = scope.ServiceProvider.GetRequiredService<NorseIdentityDbContext>();
		var authorizations = await context.Set<NorseOpenIddictAuthorization>()
			.Where(authorization => authorization.Subject == Subject)
			.Select(static authorization => new AuthorizationRow(authorization.Id, authorization.Status))
			.ToListAsync(cancellationToken);
		Guid[] ids = [.. authorizations.Select(static authorization => authorization.Id)];
		var tokens = await context.Set<NorseOpenIddictToken>()
			.Where(token => token.AuthorizationId.HasValue && ids.Contains(token.AuthorizationId.Value))
			.Select(static token => new TokenRow(token.Id, token.AuthorizationId!.Value, token.Type, token.Status, token.RedemptionDate))
			.ToListAsync(cancellationToken);
		return [.. authorizations.Select(authorization => new GrantRow(authorization.Id, authorization.Status,
			[.. tokens.Where(token => token.AuthorizationId == authorization.Id)]))];
	}

	/// <summary>Sets every token of <paramref name="authorizationId" /> to <paramref name="status" />, behind OpenIddict's back.</summary>
	/// <param name="authorizationId">The authorization.</param>
	/// <param name="status">The status to write.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	public async Task SetTokenStatusAsync(Guid authorizationId, string status, CancellationToken cancellationToken = default)
	{
		await using var scope = _app.Services.CreateAsyncScope();
		await scope.ServiceProvider.GetRequiredService<NorseIdentityDbContext>()
			.Set<NorseOpenIddictToken>()
			.Where(token => token.AuthorizationId == authorizationId)
			.ExecuteUpdateAsync(setters => setters.SetProperty(static token => token.Status, status), cancellationToken);
	}

	/// <inheritdoc />
	public async ValueTask DisposeAsync()
	{
		_pauses.ReleaseAll();
		_client.Dispose();
		// Stopped first, so the hosted services (the OpenIddict pruner) end as a host stop ends them, not faulted by disposal.
		await _app.StopAsync(CancellationToken.None);
		await _app.DisposeAsync();
		_certificate.Dispose();
	}

	async Task<HttpResponseMessage> PostAsync(string path, Dictionary<string, string> form, CancellationToken cancellationToken)
	{
		using FormUrlEncodedContent content = new(form);
		return await _client.PostAsync(new Uri(path, UriKind.Relative), content, cancellationToken);
	}

	/// <summary>The passthrough authorize endpoint: signs in the host's fixed subject with every requested scope.</summary>
	static IResult Authorize(HttpContext context, string subject)
	{
		var request = context.GetOpenIddictServerRequest() ??
			throw new InvalidOperationException("The OpenIddict request cannot be retrieved.");
		ClaimsIdentity identity = new(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, Claims.Name, Claims.Role);
		identity.AddClaim(new Claim(Claims.Subject, subject)
			.SetDestinations(Destinations.AccessToken, Destinations.IdentityToken));
		ClaimsPrincipal principal = new(identity);
		principal.SetScopes(request.GetScopes());
		return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
	}

	/// <summary>The passthrough token endpoint: re-issues the principal the presented code or refresh token carries.</summary>
	static async Task<IResult> Exchange(HttpContext context)
	{
		var request = context.GetOpenIddictServerRequest() ??
			throw new InvalidOperationException("The OpenIddict request cannot be retrieved.");
		if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
			throw new InvalidOperationException($"The test token endpoint handles codes and refresh tokens only, not '{request.GrantType}'.");
		var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		var principal = result.Principal ??
			throw new InvalidOperationException("The validated grant carries no principal.");
		return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
	}

	/// <summary>Registers <see cref="ClientId" /> once per database.</summary>
	static async Task RegisterClientAsync(WebApplication app)
	{
		await using var scope = app.Services.CreateAsyncScope();
		var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
		if (await manager.FindByClientIdAsync(ClientId) is not null)
			return;
		await manager.CreateAsync(new OpenIddictApplicationDescriptor
		{
			ClientId = ClientId,
			ClientType = ClientTypes.Public,
			RedirectUris = { RedirectUri },
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
		});
	}

	static OpenIddictServerHandlerDescriptor Recorded(OpenIddictServerHandlerDescriptor original,
		Func<IServiceProvider, IOpenIddictServerHandler<ValidateTokenContext>> inner, ConcurrentQueue<string> journal) =>
		OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
			.Import(original)
			.UseSingletonHandler(new RecordingHandler(inner, journal))
			.Build();

	/// <summary>One token response.</summary>
	/// <param name="AccessToken">The access token.</param>
	/// <param name="IdentityToken">The identity token.</param>
	/// <param name="RefreshToken">The refresh token.</param>
	public sealed record TokenSet(
		[property: JsonPropertyName("access_token")] string AccessToken,
		[property: JsonPropertyName("id_token")] string IdentityToken,
		[property: JsonPropertyName("refresh_token")] string RefreshToken);

	/// <summary>One authorization and its tokens.</summary>
	/// <param name="Id">The authorization's id.</param>
	/// <param name="Status">The authorization's status.</param>
	/// <param name="Tokens">Its tokens.</param>
	public sealed record GrantRow(Guid Id, string? Status, IReadOnlyList<TokenRow> Tokens);

	/// <summary>One token row.</summary>
	/// <param name="Id">The token's id.</param>
	/// <param name="AuthorizationId">The authorization it belongs to.</param>
	/// <param name="Type">The token type.</param>
	/// <param name="Status">The token's status.</param>
	/// <param name="RedemptionDate">When it was redeemed, if it was.</param>
	public sealed record TokenRow(Guid Id, Guid AuthorizationId, string? Type, string? Status, DateTime? RedemptionDate);

	sealed record AuthorizationRow(Guid Id, string? Status);

	/// <summary>
	///     The <see cref="IGrantTermination" /> stand-in: records every authorization it is asked to end and answers
	///     <see cref="GrantEnd.Confirmed" />. It ends nothing unless the host was started with <c>revokeOnEnd</c>, when it
	///     also runs <c>EndGrant</c>'s step 1. A hand-written fake, since the interface is internal and the proxy
	///     generator cannot see it.
	/// </summary>
	public sealed class RecordingGrantTermination : IGrantTermination
	{
		readonly ConcurrentQueue<Guid> _ended = new();
		IServiceScopeFactory? _scopes;

		/// <summary>Every authorization asked to be ended, in order.</summary>
		public IReadOnlyList<Guid> Ended => [.. _ended];

		/// <inheritdoc />
		public async Task<GrantEnd> EndAsync(Guid authorizationId, CancellationToken cancellationToken)
		{
			_ended.Enqueue(authorizationId);
			if (_scopes is null)
				return GrantEnd.Confirmed;

			await using var scope = _scopes.CreateAsyncScope();
			await GrantStatements.RevokeAuthorizationAsync(scope.ServiceProvider.GetRequiredService<NorseIdentityDbContext>(),
				authorizationId, cancellationToken);
			return GrantEnd.Confirmed;
		}

		/// <summary>From now on, revoke each authorization asked to be ended, in a scope of its own from <paramref name="scopes" />.</summary>
		/// <param name="scopes">The host's scope factory.</param>
		internal void RevokeThrough(IServiceScopeFactory scopes) =>
			_scopes = scopes;
	}

	/// <summary>
	///     Records each invocation, with the authorization id the validation resolved, then delegates to the real handler,
	///     built from the request's services.
	/// </summary>
	sealed class RecordingHandler(Func<IServiceProvider, IOpenIddictServerHandler<ValidateTokenContext>> inner,
		ConcurrentQueue<string> journal) : IOpenIddictServerHandler<ValidateTokenContext>
	{
		public ValueTask HandleAsync(ValidateTokenContext context)
		{
			var handler = inner(context.ServiceProvider);
			journal.Enqueue(
				$"{handler.GetType().Name} {context.EndpointType} {context.Principal?.GetTokenType()} {context.AuthorizationId}");
			return handler.HandleAsync(context);
		}
	}
}
