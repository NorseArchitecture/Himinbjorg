using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Components.Authorization;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     <c>auth_time</c> on the identity cookie over the production composition (spec §6.1), once per provider: the real
///     claims factory, the real store and the real stamp validator. The cookie principal is allowlisted, and the stamp
///     validator's rebuild carries <c>auth_time</c> from the ticket and nothing transient. The clock-exact stamping of each
///     credential path and the refresh-depth law are <see cref="NorseSignInManagerTests" />' facts.
/// </summary>
/// <remarks>
///     Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" /> records:
///     xUnit discovers them on each <see langword="sealed" /> provider class.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class AuthTimeSuite(IdentityFixture fixture) : IDisposable
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	const string Password = "Correct-Horse-1!";
	const string AmrClaimType = "amr";

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

	// Four persistent claims from the factory and the stamp point, plus the sign-in method ASP.NET Core Identity's own
	// password sign-in adds (amr=pwd). norse_reauth, the transient fifth, appears only on a sign-in whose landing carries
	// a valid marker.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task The_cookie_principal_carries_exactly_the_allowlisted_claims()
	{
		fixture.SkipUnlessAvailable();
		var (user, role) = await SeedAsync();
		var before = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

		var ticket = await PasswordSignInAsync(user);

		var after = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
		var claims = ClaimsIdentity;
		ticket.Principal.Claims.Select(static claim => claim.Type).ShouldBe(
		[
			claims.UserIdClaimType, claims.RoleClaimType, claims.SecurityStampClaimType, NorseClaimTypes.AuthTime,
			AmrClaimType
		], ignoreOrder: true);
		ticket.Principal.FindFirstValue(claims.UserIdClaimType).ShouldBe(user.Id.ToString());
		ticket.Principal.FindFirstValue(claims.RoleClaimType).ShouldBe(role);
		ticket.Principal.FindFirstValue(claims.SecurityStampClaimType).ShouldNotBeNullOrEmpty();
		ticket.Principal.FindFirstValue(AmrClaimType).ShouldBe("pwd");
		var authTime = ticket.Principal.FindFirst(NorseClaimTypes.AuthTime).ShouldNotBeNull();
		authTime.ValueType.ShouldBe(ClaimValueTypes.Integer64);
		long.Parse(authTime.Value, NumberStyles.None, CultureInfo.InvariantCulture).ShouldBeInRange(before, after);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task On_refreshing_principal_carries_auth_time()
	{
		fixture.SkipUnlessAvailable();
		var (user, role) = await SeedAsync();
		var ticket = await PasswordSignInAsync(user);
		var authTime = ticket.Principal.FindFirstValue(NorseClaimTypes.AuthTime).ShouldNotBeNull();
		((ClaimsIdentity)ticket.Principal.Identity!).AddClaim(new(NorseSignInManager.ReauthClaimType, "a-marker"));

		var refreshed = await ValidateStampAsync(ticket);

		var claims = ClaimsIdentity;
		refreshed.Claims.Select(static claim => claim.Type).ShouldBe(
			[claims.UserIdClaimType, claims.RoleClaimType, claims.SecurityStampClaimType, NorseClaimTypes.AuthTime],
			ignoreOrder: true);
		refreshed.FindFirstValue(claims.RoleClaimType).ShouldBe(role);
		var carried = refreshed.FindAll(NorseClaimTypes.AuthTime).ShouldHaveSingleItem();
		carried.Value.ShouldBe(authTime);
		carried.ValueType.ShouldBe(ClaimValueTypes.Integer64);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_cookie_without_auth_time_stays_without_it_across_the_stamp_validator()
	{
		fixture.SkipUnlessAvailable();
		var (user, _) = await SeedAsync();
		var ticket = await PasswordSignInAsync(user);
		var identity = (ClaimsIdentity)ticket.Principal.Identity!;
		foreach (var authTime in identity.FindAll(NorseClaimTypes.AuthTime).ToArray())
			identity.RemoveClaim(authTime);

		var refreshed = await ValidateStampAsync(ticket);

		refreshed.HasClaim(static claim => claim.Type == NorseClaimTypes.AuthTime).ShouldBeFalse();
		refreshed.FindFirstValue(ClaimsIdentity.UserIdClaimType).ShouldBe(user.Id.ToString());
	}

	ClaimsIdentityOptions ClaimsIdentity =>
		NewScope().ServiceProvider.GetRequiredService<IOptions<IdentityOptions>>().Value.ClaimsIdentity;

	// A user with a password and one role, through the real managers.
	async Task<(NorseUser User, string Role)> SeedAsync()
	{
		var seeded = await fixture.SeedUserAsync($"auth-time-{Guid.NewGuid():N}@example.com");
		var role = $"auth-time-{Guid.NewGuid():N}";
		(await fixture.CreateRoleManager().CreateAsync(new NorseRole { Name = role })).Succeeded.ShouldBeTrue();
		var withPassword = fixture.CreateUserManager();
		(await withPassword.AddPasswordAsync(
				(await withPassword.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull(), Password))
			.Succeeded.ShouldBeTrue();
		var withRole = fixture.CreateUserManager();
		(await withRole.AddToRoleAsync((await withRole.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull(), role))
			.Succeeded.ShouldBeTrue();
		return (seeded, role);
	}

	// The real sign-in manager on its own request, answering the ticket the identity cookie it wrote carries.
	async Task<AuthenticationTicket> PasswordSignInAsync(NorseUser seeded)
	{
		var signIn = SignInManager(out var context);
		var user = (await signIn.UserManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		(await signIn.PasswordSignInAsync(user, Password, isPersistent: false, lockoutOnFailure: false))
			.Succeeded.ShouldBeTrue();

		var options = context.RequestServices.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
			.Get(IdentityConstants.ApplicationScheme);
		var prefix = $"{options.Cookie.Name}=";
		var setCookie = context.Response.Headers.SetCookie
			.Single(header => header!.StartsWith(prefix, StringComparison.Ordinal))!;
		var value = setCookie[prefix.Length..setCookie.IndexOf(';', StringComparison.Ordinal)];
		return options.TicketDataFormat.Unprotect(value).ShouldNotBeNull();
	}

	// The real security-stamp validator over a ticket past the validation interval, as the cookie handler runs it.
	async Task<ClaimsPrincipal> ValidateStampAsync(AuthenticationTicket ticket)
	{
		SignInManager(out var context);
		var services = context.RequestServices;
		ticket.Properties.IssuedUtc = DateTimeOffset.UtcNow.AddDays(-1);
		var scheme = (await services.GetRequiredService<IAuthenticationSchemeProvider>()
			.GetSchemeAsync(IdentityConstants.ApplicationScheme)).ShouldNotBeNull();
		CookieValidatePrincipalContext validation = new(context, scheme,
			services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(scheme.Name), ticket);

		await services.GetRequiredService<ISecurityStampValidator>().ValidateAsync(validation);

		validation.ShouldRenew.ShouldBeTrue("the stamp validated and the principal was rebuilt");
		return validation.Principal.ShouldNotBeNull();
	}

	// One request's scoped sign-in manager over a context of its own; the scope's validator shares it.
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
