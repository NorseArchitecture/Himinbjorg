using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Components.Authorization;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.OpenIddict;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The <c>norse_reauth</c> binding over the production composition (spec §5.2, §6.1), once per provider: the real
///     claims factory, store, challenge token and data-protection ring. A password sign-in and an authenticator completion
///     landing on an authorize request bind the cookie to its marker, the allowlist gains exactly the transient claim, a
///     marker for another user binds nothing, and a refresh drops the binding. Every path, immediate and deferred through
///     <c>/_auth/complete</c>, is <see cref="ReauthBindingTests" />' gate (H5).
/// </summary>
/// <remarks>
///     Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" /> records:
///     xUnit discovers them on each <see langword="sealed" /> provider class.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class ReauthBindingSuite(IdentityFixture fixture) : IDisposable
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	const string Password = "Correct-Horse-1!";

	readonly List<IServiceScope> _scopes = [];

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <inheritdoc />
	public void Dispose()
	{
		foreach (var scope in _scopes)
			scope.Dispose();
		GC.SuppressFinalize(this);
	}

	// The four persistent claims, the password sign-in's own amr, and the one transient binding.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_password_sign_in_landing_on_a_marker_carries_exactly_the_allowlist_and_the_binding()
	{
		fixture.SkipUnlessAvailable();
		var (user, _) = await SeedAsync();
		var marker = Mint(user.Id);

		var ticket = await PasswordSignInAsync(user, Landing(marker));

		var claims = ClaimsIdentity;
		ticket.Principal.Claims.Select(static claim => claim.Type).ShouldBe(
		[
			claims.UserIdClaimType, claims.RoleClaimType, claims.SecurityStampClaimType, NorseClaimTypes.AuthTime, "amr",
			NorseSignInManager.ReauthClaimType
		], ignoreOrder: true);
		ShouldBeBoundTo(ticket.Principal, marker);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_authenticator_completion_landing_on_a_marker_binds_it()
	{
		fixture.SkipUnlessAvailable();
		var (user, key) = await SeedAsync(withAuthenticator: true);
		var marker = Mint(user.Id);
		var landing = Landing(marker);

		var minting = SignInManager(out var mintContext);
		using (ParkedReturnUrl.Park(mintContext, landing))
			(await minting.PasswordSignInAsync(await FindAsync(minting, user), Password, isPersistent: false,
				lockoutOnFailure: false)).RequiresTwoFactor.ShouldBeTrue();
		var token = (mintContext.Items[NorseSignInManager.TwoFactorChallengeItemName] as string).ShouldNotBeNull();
		var completing = SignInManager(out var context);
		var completed = await completing.TwoFactorChallengeSignInAsync(token, TotpCode.Now(key!), rememberClient: false);

		completed.Result.Succeeded.ShouldBeTrue();
		completed.ReturnUrl.ShouldBe(landing);
		var principal = Ticket(context).Principal;
		ShouldBeBoundTo(principal, marker);
		principal.FindFirstValue("amr").ShouldBe("mfa");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_marker_for_another_user_stamps_nothing()
	{
		fixture.SkipUnlessAvailable();
		var (user, _) = await SeedAsync();
		var (other, _) = await SeedAsync();

		var ticket = await PasswordSignInAsync(user, Landing(Mint(other.Id)));

		ticket.Principal.HasClaim(static claim => claim.Type == NorseSignInManager.ReauthClaimType).ShouldBeFalse();
		ticket.Principal.HasClaim(static claim => claim.Type == NorseClaimTypes.AuthTime).ShouldBeTrue();
	}

	// The refresh is handed the bound cookie and, on both slots, a landing whose marker is still valid.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Refresh_drops_norse_reauth()
	{
		fixture.SkipUnlessAvailable();
		var (user, _) = await SeedAsync();
		var marker = Mint(user.Id);
		var landing = Landing(marker);
		var signIn = SignInManager(out var signInContext);
		using (ParkedReturnUrl.Park(signInContext, landing))
			(await signIn.PasswordSignInAsync(await FindAsync(signIn, user), Password, isPersistent: false,
				lockoutOnFailure: false)).Succeeded.ShouldBeTrue();
		var signedIn = Ticket(signInContext).Principal;
		ShouldBeBoundTo(signedIn, marker);
		var authTime = signedIn.FindFirstValue(NorseClaimTypes.AuthTime);

		var refreshing = SignInManager(out var context);
		var setCookie = IdentitySetCookie(signInContext);
		context.Request.Headers.Cookie = setCookie[..setCookie.IndexOf(';', StringComparison.Ordinal)];
		context.Items[NorseSignInManager.ReauthLandingItemName] = landing;
		context.Items[NorseSignInManager.ReturnUrlItemName] = landing;
		await refreshing.RefreshSignInAsync(await FindAsync(refreshing, user));

		var refreshed = Ticket(context).Principal;
		refreshed.HasClaim(static claim => claim.Type == NorseSignInManager.ReauthClaimType).ShouldBeFalse();
		refreshed.FindAll(NorseClaimTypes.AuthTime).ShouldHaveSingleItem().Value.ShouldBe(authTime);
	}

	ClaimsIdentityOptions ClaimsIdentity =>
		NewScope().ServiceProvider.GetRequiredService<IOptions<IdentityOptions>>().Value.ClaimsIdentity;

	ReauthMarkers Markers
	{
		get
		{
			var services = NewScope().ServiceProvider;
			return new(services.GetRequiredService<IDataProtectionProvider>(), services.GetRequiredService<TimeProvider>());
		}
	}

	static ReauthMarker Mint(Guid userId) =>
		new(Guid.NewGuid(), userId, new byte[32], DateTimeOffset.UtcNow + ReauthMarkers.Lifetime);

	string Landing(ReauthMarker marker) =>
		"/connect/authorize?client_id=norse&response_type=code&norse_reauth=" + Markers.Protect(marker);

	static void ShouldBeBoundTo(ClaimsPrincipal principal, ReauthMarker marker) =>
		Guid.Parse(principal.FindAll(NorseSignInManager.ReauthClaimType).ShouldHaveSingleItem().Value)
			.ShouldBe(marker.MarkerId);

	// A user with a password and one role, through the real managers; with an authenticator enrolled and two-factor on,
	// answering the stored key.
	async Task<(NorseUser User, string? Key)> SeedAsync(bool withAuthenticator = false)
	{
		var seeded = await fixture.SeedUserAsync($"reauth-{Guid.NewGuid():N}@example.com");
		var role = $"reauth-{Guid.NewGuid():N}";
		(await fixture.CreateRoleManager().CreateAsync(new NorseRole { Name = role })).Succeeded.ShouldBeTrue();
		var withPassword = fixture.CreateUserManager();
		(await withPassword.AddPasswordAsync(
				(await withPassword.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull(), Password))
			.Succeeded.ShouldBeTrue();
		var withRole = fixture.CreateUserManager();
		(await withRole.AddToRoleAsync((await withRole.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull(), role))
			.Succeeded.ShouldBeTrue();
		if (!withAuthenticator)
			return (seeded, null);

		var enrolling = fixture.CreateUserManager();
		var enrolled = (await enrolling.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		(await enrolling.ResetAuthenticatorKeyAsync(enrolled)).Succeeded.ShouldBeTrue();
		var enabling = fixture.CreateUserManager();
		var enabled = (await enabling.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		(await enabling.SetTwoFactorEnabledAsync(enabled, true)).Succeeded.ShouldBeTrue();
		return (seeded, await fixture.CreateUserManager().GetAuthenticatorKeyAsync(
			(await enabling.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull()));
	}

	// The real sign-in manager on its own request with the landing parked as LoginHandler parks it, answering the ticket
	// the identity cookie it wrote carries.
	async Task<AuthenticationTicket> PasswordSignInAsync(NorseUser seeded, string landing)
	{
		var signIn = SignInManager(out var context);
		var user = await FindAsync(signIn, seeded);

		using (ParkedReturnUrl.Park(context, landing))
			(await signIn.PasswordSignInAsync(user, Password, isPersistent: false, lockoutOnFailure: false))
				.Succeeded.ShouldBeTrue();

		return Ticket(context);
	}

	static async Task<NorseUser> FindAsync(NorseSignInManager signIn, NorseUser seeded) =>
		(await signIn.UserManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

	// The identity cookie the request wrote, decrypted through the scheme's own ticket format.
	static AuthenticationTicket Ticket(HttpContext context)
	{
		var setCookie = IdentitySetCookie(context);
		var value = setCookie[(CookieOptions(context).Cookie.Name!.Length + 1)..setCookie.IndexOf(';', StringComparison.Ordinal)];
		return CookieOptions(context).TicketDataFormat.Unprotect(value).ShouldNotBeNull();
	}

	static string IdentitySetCookie(HttpContext context)
	{
		var prefix = $"{CookieOptions(context).Cookie.Name}=";
		return context.Response.Headers.SetCookie.Single(header => header!.StartsWith(prefix, StringComparison.Ordinal))!;
	}

	static CookieAuthenticationOptions CookieOptions(HttpContext context) =>
		context.RequestServices.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
			.Get(IdentityConstants.ApplicationScheme);

	// One request's scoped sign-in manager over a context of its own.
	NorseSignInManager SignInManager(out HttpContext context)
	{
		var scope = NewScope();
		context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
		var signIn = (NorseSignInManager)scope.ServiceProvider.GetRequiredService<SignInManager<NorseUser>>();
		signIn.Context = context;
		return signIn;
	}

	IServiceScope NewScope()
	{
		var scope = fixture.CreateOwnedScope();
		_scopes.Add(scope);
		return scope;
	}
}
