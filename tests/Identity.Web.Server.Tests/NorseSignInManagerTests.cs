using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
/// Proves <see cref="NorseSignInManager"/> actually intercepts sign-in/sign-out once
/// <c>HttpContext.Response.HasStarted</c> is genuinely true (an already-established Blazor Server
/// interactive circuit), and behaves exactly like the unmodified base class otherwise.
///
/// "Genuinely true" is not simulated via reflection or a hand-rolled fake -- these tests host a real,
/// minimal ASP.NET Core pipeline via <see cref="TestServer"/> with a real cookie authentication handler
/// wired in. Writing to the response body before sign-in flips <c>HasStarted</c> for real, the same way
/// Kestrel does, and the unmodified <see cref="SignInManager{TUser}"/> genuinely throws
/// <see cref="InvalidOperationException"/> trying to write the Set-Cookie header afterward.
/// </summary>
public sealed class NorseSignInManagerTests
{
	static readonly string _scheme = IdentityConstants.ApplicationScheme;

	[Fact]
	async Task Unmodified_SignInManager_throws_once_the_response_has_already_started()
	{
		var probe = await RunAsync(useNorseSignInManager: false, responseAlreadyStarted: true, signOut: false);

		probe.Exception.ShouldNotBeNull();
		probe.Exception.ShouldBeOfType<InvalidOperationException>();
	}

	[Fact]
	async Task Unmodified_SignInManager_signs_out_directly_and_throws_once_the_response_has_already_started()
	{
		var probe = await RunAsync(useNorseSignInManager: false, responseAlreadyStarted: true, signOut: true);

		probe.Exception.ShouldNotBeNull();
		probe.Exception.ShouldBeOfType<InvalidOperationException>();
	}

	[Fact]
	async Task NorseSignInManager_defers_sign_in_once_the_response_has_already_started()
	{
		var probe = await RunAsync(useNorseSignInManager: true, responseAlreadyStarted: true, signOut: false);

		probe.Exception.ShouldBeNull();
		probe.DeferredSignIn.Received(1).StashSignIn(_scheme, Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>());
		probe.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignOut(default!);
		probe.ItemsKey.ShouldBe(StashedSignInKey);
	}

	[Fact]
	async Task NorseSignInManager_defers_sign_out_once_the_response_has_already_started()
	{
		var probe = await RunAsync(useNorseSignInManager: true, responseAlreadyStarted: true, signOut: true);

		probe.Exception.ShouldBeNull();
		probe.DeferredSignIn.Received(1).StashSignOut(_scheme);
		probe.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignIn(default!, default!, default!);
		probe.ItemsKey.ShouldBe(StashedSignOutKey);
	}

	[Fact]
	async Task NorseSignInManager_signs_in_directly_when_the_response_has_not_started()
	{
		var probe = await RunAsync(useNorseSignInManager: true, responseAlreadyStarted: false, signOut: false);

		probe.Exception.ShouldBeNull();
		probe.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignIn(default!, default!, default!);
		probe.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignOut(default!);
		probe.ItemsKey.ShouldBeNull();
		probe.SetCookieHeaderPresent.ShouldBeTrue();
	}

	[Fact]
	async Task NorseSignInManager_signs_out_directly_when_the_response_has_not_started()
	{
		var probe = await RunAsync(useNorseSignInManager: true, responseAlreadyStarted: false, signOut: true);

		probe.Exception.ShouldBeNull();
		probe.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignIn(default!, default!, default!);
		probe.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignOut(default!);
		probe.ItemsKey.ShouldBeNull();
		probe.SetCookieHeaderPresent.ShouldBeTrue();
	}

	// Proves the reviewer's finding directly: the real, unmodified SignInManager<TUser>.SignInOrTwoFactorAsync
	// (verified by ilspycmd-decompiling the real installed Microsoft.AspNetCore.Identity assembly, .NET 11
	// preview 6) writes the partial two-factor cookie via a raw Context.SignInAsync(TwoFactorUserIdScheme, ...)
	// call that funnels through no overridable SignInManager seam at all -- not SignInWithClaimsAsync, nothing
	// else. On an established circuit that throws before SignInResult.TwoFactorRequired is ever returned, so
	// LoginHandler's RequiresTwoFactor branch (LoginHandlerTests.cs) would never actually be reached on the
	// path it exists to serve without NorseSignInManager's own SignInOrTwoFactorAsync override below.
	[Fact]
	async Task Unmodified_SignInManager_throws_writing_the_two_factor_cookie_once_the_response_has_already_started()
	{
		var probe = await RunTwoFactorAsync(useNorseSignInManager: false, responseAlreadyStarted: true);

		probe.Exception.ShouldNotBeNull();
		probe.Exception.ShouldBeOfType<InvalidOperationException>();
	}

	[Fact]
	async Task NorseSignInManager_defers_the_two_factor_cookie_once_the_response_has_already_started()
	{
		var probe = await RunTwoFactorAsync(useNorseSignInManager: true, responseAlreadyStarted: true);

		probe.Exception.ShouldBeNull();
		probe.Result.ShouldBe(SignInResult.TwoFactorRequired);
		probe.DeferredSignIn.Received(1).StashSignIn(
			IdentityConstants.TwoFactorUserIdScheme, Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>());
		probe.ItemsKey.ShouldBe(StashedTwoFactorKey);
		probe.SetCookieHeaderPresent.ShouldBeFalse();
	}

	[Fact]
	async Task NorseSignInManager_writes_the_two_factor_cookie_directly_when_the_response_has_not_started()
	{
		var probe = await RunTwoFactorAsync(useNorseSignInManager: true, responseAlreadyStarted: false);

		probe.Exception.ShouldBeNull();
		probe.Result.ShouldBe(SignInResult.TwoFactorRequired);
		probe.DeferredSignIn.DidNotReceiveWithAnyArgs().StashSignIn(default!, default!, default!);
		probe.ItemsKey.ShouldBeNull();
		probe.SetCookieHeaderPresent.ShouldBeTrue();
	}

	const string StashedSignInKey = "stashed-sign-in-key";
	const string StashedSignOutKey = "stashed-sign-out-key";
	const string StashedTwoFactorKey = "stashed-two-factor-key";

	static async Task<Probe> RunAsync(bool useNorseSignInManager, bool responseAlreadyStarted, bool signOut)
	{
		var deferredSignIn = Substitute.For<IDeferredSignIn>();
		deferredSignIn.StashSignIn(Arg.Any<string>(), Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>()).Returns(StashedSignInKey);
		deferredSignIn.StashSignOut(Arg.Any<string>()).Returns(StashedSignOutKey);

		Exception? caught = null;
		string? itemsKey = null;
		var setCookiePresent = false;

		using var host = await new HostBuilder()
			.ConfigureWebHost(webHost => webHost
				.UseTestServer()
				.ConfigureServices(services => services.AddAuthentication(_scheme).AddCookie(_scheme))
				.Configure(app => app.Run(async context =>
				{
					if (responseAlreadyStarted)
						await context.Response.WriteAsync(" ");

					NorseUser user = new() { UserName = "user@example.com", Email = "user@example.com" };
					var claimsFactory = Substitute.For<IUserClaimsPrincipalFactory<NorseUser>>();
					claimsFactory.CreateAsync(Arg.Any<NorseUser>()).Returns(new ClaimsPrincipal(new ClaimsIdentity(_scheme)));

					var userManager = Substitute.For<UserManager<NorseUser>>(
						Substitute.For<IUserStore<NorseUser>>(), null!, new PasswordHasher<NorseUser>(),
						Array.Empty<IUserValidator<NorseUser>>(), Array.Empty<IPasswordValidator<NorseUser>>(),
						new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null!,
						NullLogger<UserManager<NorseUser>>.Instance);

					HttpContextAccessor accessor = new() { HttpContext = context };
					var schemes = Substitute.For<IAuthenticationSchemeProvider>();
					var confirmation = Substitute.For<IUserConfirmation<NorseUser>>();

					SignInManager<NorseUser> signInManager = useNorseSignInManager ?
						new NorseSignInManager(
							userManager, accessor, claimsFactory, Options.Create(new IdentityOptions()),
							NullLogger<SignInManager<NorseUser>>.Instance, schemes, confirmation, deferredSignIn) :
						new SignInManager<NorseUser>(
							userManager, accessor, claimsFactory, Options.Create(new IdentityOptions()),
							NullLogger<SignInManager<NorseUser>>.Instance, schemes, confirmation);

					try
					{
						if (signOut)
							await signInManager.SignOutAsync();
						else
							await signInManager.SignInWithClaimsAsync(user, isPersistent: false, additionalClaims: []);
					}
					catch (Exception ex)
					{
						caught = ex;
					}

					itemsKey = context.Items.TryGetValue(NorseSignInManager.DeferredSignInKeyItemName, out var value) ?
						value as string :
						null;
					setCookiePresent = context.Response.Headers.ContainsKey("Set-Cookie");
				})))
			.StartAsync();

		using var client = host.GetTestServer().CreateClient();
		await client.GetAsync(new Uri("/", UriKind.Relative));

		return new Probe(caught, deferredSignIn, itemsKey, setCookiePresent);
	}

	// SignInOrTwoFactorAsync itself is protected and NorseSignInManager is sealed, so there is no
	// exposer-subclass trick available here the way there is for SignInWithClaimsAsync/SignOutAsync --
	// driven instead through PasswordSignInAsync, the real public entry point LoginHandler itself calls,
	// which is arguably more faithful anyway: it exercises the actual call path, not an isolated method.
	static async Task<TwoFactorProbe> RunTwoFactorAsync(bool useNorseSignInManager, bool responseAlreadyStarted)
	{
		var deferredSignIn = Substitute.For<IDeferredSignIn>();
		deferredSignIn.StashSignIn(Arg.Any<string>(), Arg.Any<ClaimsPrincipal>(), Arg.Any<AuthenticationProperties>()).Returns(StashedTwoFactorKey);

		Exception? caught = null;
		string? itemsKey = null;
		var setCookiePresent = false;
		SignInResult? result = null;

		using var host = await new HostBuilder()
			.ConfigureWebHost(webHost => webHost
				.UseTestServer()
				.ConfigureServices(services => services
					.AddAuthentication(_scheme)
					.AddCookie(_scheme)
					.AddCookie(IdentityConstants.TwoFactorUserIdScheme))
				.Configure(app => app.Run(async context =>
				{
					if (responseAlreadyStarted)
						await context.Response.WriteAsync(" ");

					NorseUser user = new() { UserName = "user@example.com", Email = "user@example.com" };
					var claimsFactory = Substitute.For<IUserClaimsPrincipalFactory<NorseUser>>();
					claimsFactory.CreateAsync(Arg.Any<NorseUser>()).Returns(new ClaimsPrincipal(new ClaimsIdentity(_scheme)));

					// CanSignInAsync/IsLockedOut both pass unstubbed (IdentityOptions defaults to no
					// confirmation requirements; SupportsUserLockout defaults false on an unstubbed
					// substitute) -- CheckPasswordAsync true is the only thing CheckPasswordSignInAsync
					// needs to report Success, then PasswordSignInAsync calls SignInOrTwoFactorAsync,
					// which re-checks 2FA itself via the three stubs below (SupportsUserTwoFactor,
					// GetTwoFactorEnabledAsync, a non-empty GetValidTwoFactorProvidersAsync) -- genuinely
					// requires 2FA, the one case the reviewer's finding is about.
					var userManager = Substitute.For<UserManager<NorseUser>>(
						Substitute.For<IUserStore<NorseUser>>(), null!, new PasswordHasher<NorseUser>(),
						Array.Empty<IUserValidator<NorseUser>>(), Array.Empty<IPasswordValidator<NorseUser>>(),
						new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null!,
						NullLogger<UserManager<NorseUser>>.Instance);
					userManager.CheckPasswordAsync(user, "correct-horse").Returns(true);
					userManager.SupportsUserTwoFactor.Returns(true);
					userManager.GetTwoFactorEnabledAsync(user).Returns(true);
					userManager.GetValidTwoFactorProvidersAsync(user).Returns((IList<string>)["Authenticator"]);
					userManager.GetUserIdAsync(user).Returns(user.Id.ToString());

					HttpContextAccessor accessor = new() { HttpContext = context };
					var schemes = Substitute.For<IAuthenticationSchemeProvider>();
					// IsTwoFactorClientRememberedAsync short-circuits to false when this scheme isn't
					// registered on the manager's own copy -- unstubbed (null) is exactly "not
					// remembered", forcing the genuinely-requires-2FA branch every time.
					schemes.GetSchemeAsync(IdentityConstants.TwoFactorUserIdScheme)
						.Returns(new AuthenticationScheme(IdentityConstants.TwoFactorUserIdScheme, null, typeof(CookieAuthenticationHandler)));
					var confirmation = Substitute.For<IUserConfirmation<NorseUser>>();

					SignInManager<NorseUser> signInManager = useNorseSignInManager ?
						new NorseSignInManager(
							userManager, accessor, claimsFactory, Options.Create(new IdentityOptions()),
							NullLogger<SignInManager<NorseUser>>.Instance, schemes, confirmation, deferredSignIn) :
						new SignInManager<NorseUser>(
							userManager, accessor, claimsFactory, Options.Create(new IdentityOptions()),
							NullLogger<SignInManager<NorseUser>>.Instance, schemes, confirmation);

					try
					{
						result = await signInManager.PasswordSignInAsync(
							user, "correct-horse", isPersistent: false, lockoutOnFailure: false);
					}
					catch (Exception ex)
					{
						caught = ex;
					}

					itemsKey = context.Items.TryGetValue(NorseSignInManager.DeferredSignInKeyItemName, out var value) ?
						value as string :
						null;
					setCookiePresent = context.Response.Headers.ContainsKey("Set-Cookie");
				})))
			.StartAsync();

		using var client = host.GetTestServer().CreateClient();
		await client.GetAsync(new Uri("/", UriKind.Relative));

		return new TwoFactorProbe(caught, deferredSignIn, itemsKey, setCookiePresent, result);
	}

	sealed record Probe(Exception? Exception, IDeferredSignIn DeferredSignIn, string? ItemsKey, bool SetCookieHeaderPresent);

	sealed record TwoFactorProbe(
		Exception? Exception, IDeferredSignIn DeferredSignIn, string? ItemsKey, bool SetCookieHeaderPresent, SignInResult? Result);
}
