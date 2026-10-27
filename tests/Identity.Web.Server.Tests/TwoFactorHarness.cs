using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Identity.EntityFramework;
using Norse.Infrastructure.Web.Server.DeferredSignIn;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     A real, minimal ASP.NET Core pipeline (<see cref="TestServer" />) around a DI-built
///     <see cref="NorseSignInManager" />: the four Identity cookie schemes with their real security-stamp
///     validators, an ephemeral data-protection ring, a <see cref="FakeTimeProvider" /> driving both the
///     cookie handlers and <see cref="SecurityStampValidatorOptions" />, and Midgard's real
///     <c>/_auth/complete</c> endpoint. The user manager is a substitute answering for one user with an
///     authenticator enrolled; <see cref="Stamp" /> is mutable so a test can rotate the security stamp
///     between requests. Each <see cref="RunAsync{T}" /> is one genuine HTTP request; writing to the
///     response body first flips <c>HasStarted</c> the way Kestrel does.
/// </summary>
sealed class TwoFactorHarness : IDisposable
{
	public const string Password = "correct-horse";
	public const string AuthenticatorCode = "123456";
	public const string RecoveryCode = "abcde-fghij";
	public const string ExternalProvider = "Google";
	public const string ExternalProviderKey = "google-subject";
	public static readonly TimeSpan ValidationInterval = TimeSpan.FromMinutes(30);

	readonly IHost _host;
	HttpClient? _client;
	Func<NorseSignInManager, Task<object?>> _act = static _ => Task.FromResult<object?>(null);
	bool _responseAlreadyStarted;
	object? _value;
	Exception? _exception;
	string? _token;
	string? _identityKey;
	string? _rememberKey;

	TwoFactorHarness(bool realDeferredSignIn)
	{
		UserManager = Substitute.For<UserManager<NorseUser>>(
			Substitute.For<IUserStore<NorseUser>>(), null!, new PasswordHasher<NorseUser>(),
			Array.Empty<IUserValidator<NorseUser>>(), Array.Empty<IPasswordValidator<NorseUser>>(),
			new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null!,
			NullLogger<UserManager<NorseUser>>.Instance);
		UserManager.SupportsUserTwoFactor.Returns(true);
		UserManager.SupportsUserSecurityStamp.Returns(true);
		UserManager.SupportsUserLockout.Returns(true);
		UserManager.GetTwoFactorEnabledAsync(User).Returns(true);
		UserManager.GetValidTwoFactorProvidersAsync(User)
			.Returns((IList<string>)[TokenOptions.DefaultAuthenticatorProvider]);
		UserManager.GetUserIdAsync(User).Returns(UserId);
		UserManager.GetUserId(Arg.Any<ClaimsPrincipal>())
			.Returns(call => call.Arg<ClaimsPrincipal>().FindFirstValue(ClaimTypes.NameIdentifier));
		UserManager.GetSecurityStampAsync(User).Returns(_ => Stamp);
		UserManager.FindByIdAsync(UserId).Returns(User);
		UserManager.FindByLoginAsync(ExternalProvider, ExternalProviderKey).Returns(User);
		UserManager.CheckPasswordAsync(User, Password).Returns(true);
		UserManager.VerifyTwoFactorTokenAsync(User, TokenOptions.DefaultAuthenticatorProvider, AuthenticatorCode)
			.Returns(true);
		UserManager.AccessFailedAsync(User).Returns(IdentityResult.Success);
		UserManager.ResetAccessFailedCountAsync(User).Returns(IdentityResult.Success);
		UserManager.RedeemTwoFactorRecoveryCodeAsync(User, RecoveryCode).Returns(IdentityResult.Success);

		// A fresh principal per call: SignInWithClaimsAsync mutates the identity it is handed.
		ClaimsFactory.CreateAsync(User)
			.Returns(_ => new ClaimsPrincipal(new ClaimsIdentity(
				[new Claim(ClaimTypes.NameIdentifier, UserId)], IdentityConstants.ApplicationScheme)));

		_host = new HostBuilder()
			.ConfigureWebHost(webHost => webHost
				.UseTestServer()
				.ConfigureServices(services =>
				{
					services.AddRouting();
					services.AddHttpContextAccessor();
					services.AddSingleton<TimeProvider>(Clock);
					services.AddDataProtection().UseEphemeralDataProtectionProvider();
					services.AddAuthentication(IdentityConstants.ApplicationScheme).AddIdentityCookies();
					services.Configure<SecurityStampValidatorOptions>(options =>
					{
						options.ValidationInterval = ValidationInterval;
						options.TimeProvider = Clock;
					});
					services.PostConfigureAll<CookieAuthenticationOptions>(options => options.TimeProvider = Clock);
					services
						.AddSingleton(UserManager)
						.AddSingleton(ClaimsFactory)
						.AddSingleton(Substitute.For<IUserConfirmation<NorseUser>>())
						.AddScoped<NorseSignInManager>()
						.AddScoped<SignInManager<NorseUser>>(static sp => sp.GetRequiredService<NorseSignInManager>())
						.AddScoped<ISecurityStampValidator, SecurityStampValidator<NorseUser>>()
						.AddScoped<ITwoFactorSecurityStampValidator, TwoFactorSecurityStampValidator<NorseUser>>();
					if (realDeferredSignIn)
						services.AddDeferredSignIn();
					else
						services.AddSingleton(Substitute.For<IDeferredSignIn>());
				})
				.Configure(app =>
				{
					app.UseRouting();
					// As on the real pipeline: the default (application) scheme is authenticated before anything
					// writes to the response, so its cookie handler is initialized while the response can still
					// register its OnStarting callback. Any other scheme's first authenticate on a started response
					// throws from CookieAuthenticationHandler.InitializeHandlerAsync -- on Kestrel just the same.
					app.UseAuthentication();
					app.UseEndpoints(static endpoints => endpoints.MapDeferredSignIn());
					app.Run(HandleAsync);
				}))
			.Build();
	}

	public NorseUser User { get; } = new() { UserName = "user@example.com", Email = "user@example.com" };

	public string UserId =>
		User.Id.ToString();

	/// <summary>The user's current security stamp; assign to rotate it between requests.</summary>
	public string Stamp { get; set; } = Guid.NewGuid().ToString();

	public UserManager<NorseUser> UserManager { get; }

	public IUserClaimsPrincipalFactory<NorseUser> ClaimsFactory { get; } =
		Substitute.For<IUserClaimsPrincipalFactory<NorseUser>>();

	public FakeTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);

	public IServiceProvider Services =>
		_host.Services;

	public IDeferredSignIn DeferredSignIn =>
		Services.GetRequiredService<IDeferredSignIn>();

	public string SecurityStampClaimType =>
		Services.GetRequiredService<IOptions<IdentityOptions>>().Value.ClaimsIdentity.SecurityStampClaimType;

	public ITimeLimitedDataProtector ChallengeProtector =>
		Services.GetRequiredService<IDataProtectionProvider>()
			.CreateProtector(TwoFactorChallenge.Purpose)
			.ToTimeLimitedDataProtector();

	public static async Task<TwoFactorHarness> StartAsync(bool realDeferredSignIn = false)
	{
		TwoFactorHarness harness = new(realDeferredSignIn);
		await harness._host.StartAsync();
		harness._client = harness._host.GetTestServer().CreateClient();
		return harness;
	}

	/// <summary>The <c>name=value</c> pair of a <c>Set-Cookie</c> header, ready for a <c>Cookie</c> header.</summary>
	public static string CookieOf(string setCookie) =>
		setCookie[..setCookie.IndexOf(';', StringComparison.Ordinal)];

	/// <summary>Runs <paramref name="act" /> against the DI-built manager on one real request.</summary>
	public async Task<Probe<T>> RunAsync<T>(Func<NorseSignInManager, Task<T>> act, bool responseAlreadyStarted = false,
		string? cookie = null)
	{
		_act = async manager => await act(manager);
		_responseAlreadyStarted = responseAlreadyStarted;
		(_value, _exception, _token, _identityKey, _rememberKey) = (null, null, null, null, null);

		using HttpRequestMessage request = new(HttpMethod.Get, new Uri("/", UriKind.Relative));
		if (cookie is not null)
			request.Headers.Add("Cookie", cookie);
		using var response = await _client!.SendAsync(request);

		return new(_value is T value ? value : default, _exception, _token, _identityKey, _rememberKey,
			SetCookiesOf(response));
	}

	/// <summary>Runs an act without a result; <see cref="Probe{T}.Value" /> is meaningless on the answer.</summary>
	public Task<Probe<bool>> RunAsync(Func<NorseSignInManager, Task> act, bool responseAlreadyStarted = false,
		string? cookie = null) =>
		RunAsync(async manager =>
		{
			await act(manager);
			return true;
		}, responseAlreadyStarted, cookie);

	/// <summary>A plain GET (the deferred completion endpoint), answering the <c>Set-Cookie</c> headers it wrote.</summary>
	public async Task<IReadOnlyList<string>> GetSetCookiesAsync(string url)
	{
		using var response = await _client!.GetAsync(new Uri(url, UriKind.Relative));
		response.EnsureSuccessStatusCode();
		return SetCookiesOf(response);
	}

	/// <summary>Decrypts a scheme's cookie through the registered handler's own ticket format.</summary>
	public AuthenticationTicket Decrypt(string scheme, string setCookie)
	{
		var options = Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(scheme);
		var value = CookieOf(setCookie)[(options.Cookie.Name!.Length + 1)..];
		return options.TicketDataFormat.Unprotect(value).ShouldNotBeNull();
	}

	public void Dispose()
	{
		_client?.Dispose();
		_host.Dispose();
	}

	static IReadOnlyList<string> SetCookiesOf(HttpResponseMessage response) =>
		response.Headers.TryGetValues("Set-Cookie", out var values) ?
			[.. values] :
			[];

	async Task HandleAsync(HttpContext context)
	{
		if (_responseAlreadyStarted)
			await context.Response.WriteAsync(" ");

		var manager = context.RequestServices.GetRequiredService<NorseSignInManager>();
		try
		{
			_value = await _act(manager);
		}
		catch (Exception exception)
		{
			_exception = exception;
		}

		_token = context.Items[NorseSignInManager.TwoFactorChallengeItemName] as string;
		_identityKey = context.Items[NorseSignInManager.DeferredSignInKeyItemName] as string;
		_rememberKey = context.Items[NorseSignInManager.DeferredRememberClientKeyItemName] as string;
	}

	/// <summary>What one request left behind.</summary>
	public sealed record Probe<T>(
		T? Value,
		Exception? Exception,
		string? Token,
		string? IdentityKey,
		string? RememberKey,
		IReadOnlyList<string> SetCookies)
	{
		public bool SetCookieHeaderPresent =>
			SetCookies.Count > 0;

		/// <summary>The <c>Set-Cookie</c> header for <paramref name="cookieName" />, or <see langword="null" />.</summary>
		public string? SetCookieFor(string cookieName) =>
			SetCookies.SingleOrDefault(header => header.StartsWith($"{cookieName}=", StringComparison.Ordinal));
	}
}
