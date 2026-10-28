using System.IdentityModel.Tokens.Jwt;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Norse.Identity.Web.Server.Tests.ExternalLogin;

/// <summary>
///     A test-only remote scheme that behaves like a provider without one: its challenge writes the real correlation
///     cookie and redirects to <see cref="FakeRemote.AuthorizePath" /> carrying the protected properties as
///     <c>state</c>; that endpoint redirects to the scheme's <c>CallbackPath</c> with the id token payload the test chose;
///     and the callback unprotects <c>state</c>, validates the correlation cookie, runs the production
///     <c>OnTokenValidated</c> over the token (the verified email and the provider key) and answers its ticket or its
///     failure.
/// </summary>
/// <param name="options">The scheme's options.</param>
/// <param name="logger">The logger factory.</param>
/// <param name="encoder">The URL encoder.</param>
sealed class FakeRemoteAuthenticationHandler(
	IOptionsMonitor<FakeRemoteOptions> options,
	ILoggerFactory logger,
	UrlEncoder encoder)
	: RemoteAuthenticationHandler<FakeRemoteOptions>(options, logger, encoder)
{
	/// <inheritdoc />
	protected override Task HandleChallengeAsync(AuthenticationProperties properties)
	{
		if (string.IsNullOrEmpty(properties.RedirectUri))
			properties.RedirectUri = OriginalPathBase + OriginalPath + Request.QueryString;

		GenerateCorrelationId(properties);
		Response.Redirect(UriHelper.BuildRelative(OriginalPathBase, FakeRemote.AuthorizePath,
			QueryString.Create("state", Options.StateDataFormat.Protect(properties))));
		return Task.CompletedTask;
	}

	/// <inheritdoc />
	protected override Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
	{
		var properties = Options.StateDataFormat.Unprotect(Request.Query["state"]);
		if (properties is null)
			return Task.FromResult(HandleRequestResult.Fail("The state was missing or invalid."));
		if (!ValidateCorrelationId(properties))
			return Task.FromResult(HandleRequestResult.Fail("Correlation failed.", properties));

		// The id token the test chose, its claims on the principal under their own names in the case-sensitive identity
		// the OIDC handler builds (inbound mapping off), and the one production OnTokenValidated every OIDC scheme runs,
		// handed the token as the RC3 handler hands it: a JwtSecurityToken over the same bytes.
		JsonWebToken idToken = new("""{"alg":"none"}""", Request.Query["payload"].ToString());
		TokenValidatedContext validated = new(Context, Scheme, new OpenIdConnectOptions(),
			new(new CaseSensitiveClaimsIdentity(idToken.Claims, Scheme.Name)), properties)
		{
			SecurityToken = new JwtSecurityToken(idToken.EncodedToken)
		};
		ExternalProviders.OnTokenValidated(validated);
		return Task.FromResult(validated.Result is { Failure: { } failure } ?
			HandleRequestResult.Fail(failure, properties) :
			HandleRequestResult.Success(new(validated.Principal!, properties, Scheme.Name)));
	}
}

/// <summary>The fake remote scheme's options: a <c>state</c> format over the host's data protection.</summary>
sealed class FakeRemoteOptions : RemoteAuthenticationOptions
{
	public FakeRemoteOptions() =>
		CallbackPath = FakeRemote.CallbackPath;

	/// <summary>Protects the challenge's properties into <c>state</c>; set from the host's provider at post-configure.</summary>
	public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; } = null!;
}

/// <summary>Registers and maps the fake remote scheme.</summary>
static class FakeRemote
{
	/// <summary>The fake scheme's name.</summary>
	public const string Scheme = "Fake";

	/// <summary>The fake scheme's display name.</summary>
	public const string DisplayName = "Fake Provider";

	/// <summary>The fake provider's authorization endpoint.</summary>
	public const string AuthorizePath = "/fake-provider/authorize";

	/// <summary>The fake scheme's callback path.</summary>
	public const string CallbackPath = "/signin-fake";

	/// <summary>The data-protection purpose of <see cref="FakeRemoteOptions.StateDataFormat" />.</summary>
	public const string StatePurpose = "FakeRemote.State";

	/// <summary>
	///     Registers the fake through the framework's <c>AddRemoteScheme</c>, signing into the external cookie and
	///     sharing the one production failure handler.
	/// </summary>
	public static AuthenticationBuilder AddFakeRemote(this AuthenticationBuilder builder)
	{
		builder.Services.AddSingleton<IPostConfigureOptions<FakeRemoteOptions>, FakeRemotePostConfigure>();
		return builder.AddRemoteScheme<FakeRemoteOptions, FakeRemoteAuthenticationHandler>(Scheme, DisplayName, o =>
		{
			o.SignInScheme = IdentityConstants.ExternalScheme;
			ExternalProviders.ConfigureRemoteFailure(o);
		});
	}

	/// <summary>
	///     Maps the fake provider's authorization endpoint: it redirects to the callback with <c>state</c> and the id
	///     token <c>payload</c> (JSON, its <c>sub</c> included) the test appended.
	/// </summary>
	public static void MapFakeProvider(this IEndpointRouteBuilder endpoints) =>
		endpoints.MapGet(AuthorizePath, (HttpContext context, string state, string? payload) =>
			Results.Redirect(UriHelper.BuildRelative(context.Request.PathBase, CallbackPath,
				QueryString.Create(new Dictionary<string, string?>
				{
					["state"] = state,
					["payload"] = payload
				}))));

	/// <summary>The state format a test reads the challenged properties back with.</summary>
	public static ISecureDataFormat<AuthenticationProperties> StateFormat(IDataProtectionProvider provider) =>
		new PropertiesDataFormat(provider.CreateProtector(StatePurpose));

	sealed class FakeRemotePostConfigure(IDataProtectionProvider dataProtection) : IPostConfigureOptions<FakeRemoteOptions>
	{
		public void PostConfigure(string? name, FakeRemoteOptions options) =>
			options.StateDataFormat ??= StateFormat(dataProtection);
	}
}
