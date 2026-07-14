using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Norse.Infrastructure.Web.Server.DeferredSignIn;
using NSubstitute;

namespace Norse.Identity.Tests;

/// <summary>
/// Proves <see cref="NorseSignInManager"/> actually intercepts sign-in/sign-out once
/// <c>HttpContext.Response.HasStarted</c> is genuinely true (an already-established Blazor Server
/// interactive circuit), and behaves exactly like the unmodified base class otherwise.
///
/// "Genuinely true" is not simulated via reflection or a hand-rolled fake -- these tests host a real,
/// minimal ASP.NET Core pipeline via <see cref="TestServer"/> with a real cookie authentication handler
/// wired in. Writing to the response body before sign-in flips <c>HasStarted</c> for real, the same way
/// Kestrel does, and the unmodified <see cref="SignInManager{TUser}"/> genuinely throws
/// <see cref="InvalidOperationException"/> trying to write the Set-Cookie header afterward -- this is the
/// exact crash the design note (2026-07-14-deferred-signin-fix.md) reports from the live composed system.
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

	const string StashedSignInKey = "stashed-sign-in-key";
	const string StashedSignOutKey = "stashed-sign-out-key";

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
						await context.Response.WriteAsync(" ").ConfigureAwait(false);

					var user = new NorseUser { UserName = "user@example.com", Email = "user@example.com" };
					var claimsFactory = Substitute.For<IUserClaimsPrincipalFactory<NorseUser>>();
					claimsFactory.CreateAsync(Arg.Any<NorseUser>()).Returns(new ClaimsPrincipal(new ClaimsIdentity(_scheme)));

					var userManager = Substitute.For<UserManager<NorseUser>>(
						Substitute.For<IUserStore<NorseUser>>(), null!, new PasswordHasher<NorseUser>(),
						Array.Empty<IUserValidator<NorseUser>>(), Array.Empty<IPasswordValidator<NorseUser>>(),
						new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null!,
						NullLogger<UserManager<NorseUser>>.Instance);

					var accessor = new HttpContextAccessor { HttpContext = context };
					var schemes = Substitute.For<IAuthenticationSchemeProvider>();
					var confirmation = Substitute.For<IUserConfirmation<NorseUser>>();

					SignInManager<NorseUser> signInManager = useNorseSignInManager
						? new NorseSignInManager(
							userManager, accessor, claimsFactory, Options.Create(new IdentityOptions()),
							NullLogger<SignInManager<NorseUser>>.Instance, schemes, confirmation, deferredSignIn)
						: new SignInManager<NorseUser>(
							userManager, accessor, claimsFactory, Options.Create(new IdentityOptions()),
							NullLogger<SignInManager<NorseUser>>.Instance, schemes, confirmation);

					try
					{
						if (signOut)
							await signInManager.SignOutAsync().ConfigureAwait(false);
						else
							await signInManager.SignInWithClaimsAsync(user, isPersistent: false, additionalClaims: []).ConfigureAwait(false);
					}
					catch (Exception ex)
					{
						caught = ex;
					}

					itemsKey = context.Items.TryGetValue(NorseSignInManager.DeferredSignInKeyItemName, out var value)
						? value as string
						: null;
					setCookiePresent = context.Response.Headers.ContainsKey("Set-Cookie");
				})))
			.StartAsync().ConfigureAwait(false);

		using var client = host.GetTestServer().CreateClient();
		await client.GetAsync(new Uri("/", UriKind.Relative)).ConfigureAwait(false);

		return new Probe(caught, deferredSignIn, itemsKey, setCookiePresent);
	}

	sealed record Probe(Exception? Exception, IDeferredSignIn DeferredSignIn, string? ItemsKey, bool SetCookieHeaderPresent);
}
