using System.Collections.Concurrent;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.FluentUI.AspNetCore.Components;
using Norse.Abstractions.Components.Authorization;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.ExternalLogin;
using Norse.Identity.Web.Server.OpenIddict;

namespace Norse.Identity.Web.Server.Tests.ExternalLogin;

/// <summary>
///     The external-login callback page (<see cref="ExternalLoginCallback" />, static SSR) over the real start leg: a
///     slim <see cref="TestServer" /> host mapping <see cref="CallbackTestRoot" /> and <c>MapNorseExternalLoginEndpoints</c>,
///     the fake remote scheme registered through <c>AddRemoteScheme</c> with the one production failure handler, and the
///     real managers over the real <see cref="NorseUserStore" /> on the provider's shared fixture (the registration
///     branch persists and erases). Every fact walks start → fake provider → <c>CallbackPath</c> →
///     <c>/Account/ExternalLogin</c> with a cookie jar driven by hand, so the external cookie is always the one the
///     remote handler wrote, never a seeded one.
/// </summary>
/// <remarks>
///     The managers come from a fixture scope per request: a second host over the same provider would reuse the
///     fixture's compiled model, and with it the fixture's protector (see <see cref="IdentityFixture" />). The sign-in
///     manager is built here, over this host's request, schemes and data protection.
/// </remarks>
public abstract partial class ExternalLoginCallbackSuite : IAsyncDisposable
{
	const string Landing = "/Account/Manage?x=1";
	const string ConfirmationLink = "http://localhost/Account/ConfirmEmail?userId=";
	const string TestRedeemPath = "/test/redeem";

	const string UnverifiedEmailMessage =
		"Your sign-in provider did not share a verified email address. Register with a password, then link this provider from your account.";

	readonly IdentityFixture _fixture;
	readonly CapturingEmailSender _emails = new();
	WebApplication? _app;
	HttpClient? _client;

	/// <summary>Binds the suite to the provider's shared fixture.</summary>
	/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
	protected ExternalLoginCallbackSuite(IdentityFixture fixture) =>
		_fixture = fixture;

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	/// <inheritdoc />
	public async ValueTask DisposeAsync()
	{
		_client?.Dispose();
		if (_app is not null)
			await _app.DisposeAsync();
		GC.SuppressFinalize(this);
	}

	[Fact]
	protected async Task A_known_login_signs_in_and_lands_on_the_resolved_return_url()
	{
		_fixture.SkipUnlessAvailable();
		var subject = NewSubject();
		var user = await SeedWithLoginAsync(subject);
		CookieJar jar = new();
		await StartAsync();

		using var callback = await WalkToCallbackAsync(jar, subject, user.Email!, Landing);
		using var page = await SendAsync(jar, HttpMethod.Get, LocationOf(callback));

		LocationOf(page).ShouldBe(Landing);
		var identity = Ticket(IdentityConstants.ApplicationScheme, page).ShouldNotBeNull();
		identity.Principal.FindFirstValue(ClaimTypes.NameIdentifier).ShouldBe(user.Id.ToString());
		identity.Principal.FindFirstValue(ClaimTypes.AuthenticationMethod).ShouldBe(FakeRemote.Scheme);
		Deletes(page, IdentityConstants.ExternalScheme).ShouldBeTrue();
	}

	[Fact]
	protected async Task A_foreign_return_url_lands_on_the_app_root()
	{
		_fixture.SkipUnlessAvailable();
		var subject = NewSubject();
		var user = await SeedWithLoginAsync(subject);
		CookieJar jar = new();
		await StartAsync();

		using var callback = await WalkToCallbackAsync(jar, subject, user.Email!, Landing);
		// The page's own Resolve is the guard here: the start already resolved its candidate, so the replayed
		// page URL carries the hostile one past it.
		var hostile = ReplaceReturnUrl(LocationOf(callback), "https://evil.test/");
		using var page = await SendAsync(jar, HttpMethod.Get, hostile);

		LocationOf(page).ShouldBe("/");
		Ticket(IdentityConstants.ApplicationScheme, page).ShouldNotBeNull();
	}

	[Fact]
	protected async Task An_external_sign_in_for_a_two_factor_account_requires_the_challenge()
	{
		_fixture.SkipUnlessAvailable();
		var subject = NewSubject();
		var user = await SeedWithLoginAsync(subject);
		var key = await EnableTwoFactorAsync(user.Id);
		CookieJar jar = new();
		await StartAsync();

		using var callback = await WalkToCallbackAsync(jar, subject, user.Email!, Landing);
		using var page = await SendAsync(jar, HttpMethod.Get, LocationOf(callback));

		var challengeUrl = LocationOf(page);
		challengeUrl.ShouldStartWith("/Account/LoginWith2fa?challenge=");
		Deletes(page, IdentityConstants.ExternalScheme).ShouldBeTrue("the external cookie is cleared before the challenge");
		Ticket(IdentityConstants.ApplicationScheme, page).ShouldBeNull();
		jar.Has(CookieName(IdentityConstants.ExternalScheme)).ShouldBeFalse();

		var token = QueryHelpers.ParseQuery(challengeUrl[challengeUrl.IndexOf('?', StringComparison.Ordinal)..])["challenge"]
			.ToString();
		using var redeemed = await SendAsync(jar, HttpMethod.Get,
			$"{TestRedeemPath}?challenge={Uri.EscapeDataString(token)}&code={TotpCode.Now(key)}");

		redeemed.StatusCode.ShouldBe(HttpStatusCode.OK);
		(await redeemed.Content.ReadAsStringAsync(Cancellation)).ShouldBe(Landing);
		var identity = Ticket(IdentityConstants.ApplicationScheme, redeemed).ShouldNotBeNull();
		identity.Principal.FindFirstValue(ClaimTypes.NameIdentifier).ShouldBe(user.Id.ToString());
		identity.Principal.FindFirstValue(ClaimTypes.AuthenticationMethod).ShouldBe(FakeRemote.Scheme);
		identity.Principal.FindFirstValue("amr").ShouldBe("mfa");
	}

	[Fact]
	protected async Task An_external_sign_in_for_a_locked_out_account_redirects_to_lockout()
	{
		_fixture.SkipUnlessAvailable();
		var subject = NewSubject();
		var user = await SeedWithLoginAsync(subject);
		var userManager = _fixture.CreateUserManager();
		var read = (await userManager.FindByIdAsync(user.Id.ToString())).ShouldNotBeNull();
		(await userManager.SetLockoutEndDateAsync(read, DateTimeOffset.UtcNow.AddHours(1))).Succeeded.ShouldBeTrue();
		CookieJar jar = new();
		await StartAsync();

		using var callback = await WalkToCallbackAsync(jar, subject, user.Email!, Landing);
		using var page = await SendAsync(jar, HttpMethod.Get, LocationOf(callback));

		LocationOf(page).ShouldBe("/Account/Lockout");
		Ticket(IdentityConstants.ApplicationScheme, page).ShouldBeNull();
		Deletes(page, IdentityConstants.ExternalScheme).ShouldBeTrue("the external cookie is cleared");
	}

	[Fact]
	protected async Task A_missing_external_cookie_renders_an_error_in_place()
	{
		_fixture.SkipUnlessAvailable();
		var subject = NewSubject();
		var user = await SeedWithLoginAsync(subject);
		CookieJar jar = new();
		await StartAsync();

		using var callback = await WalkToCallbackAsync(jar, subject, user.Email!, Landing);
		jar.Remove(CookieName(IdentityConstants.ExternalScheme));
		using var page = await SendAsync(jar, HttpMethod.Get, LocationOf(callback));

		page.StatusCode.ShouldBe(HttpStatusCode.OK);
		var html = await page.Content.ReadAsStringAsync(Cancellation);
		html.ShouldContain("Error loading external login information.");
		html.ShouldContain("href=\"/Account/Login\"");
		Ticket(IdentityConstants.ApplicationScheme, page).ShouldBeNull();
	}

	[Fact]
	protected async Task A_callback_without_the_browsers_correlation_cookie_signs_in_nothing()
	{
		_fixture.SkipUnlessAvailable();
		var subject = NewSubject();
		var user = await SeedWithLoginAsync(subject);
		CookieJar browser = new();
		await StartAsync();

		var providerReturn = await WalkToProviderReturnAsync(browser, subject, user.Email!, Landing);
		CookieJar attacker = new();
		using var callback = await SendAsync(attacker, HttpMethod.Get, providerReturn);

		LocationOf(callback).ShouldStartWith("/Account/ExternalLogin?RemoteError=");
		Ticket(IdentityConstants.ExternalScheme, callback).ShouldBeNull();
		Ticket(IdentityConstants.ApplicationScheme, callback).ShouldBeNull();
		attacker.Has(CookieName(IdentityConstants.ExternalScheme)).ShouldBeFalse();
	}

	[Fact]
	protected async Task A_provider_failure_renders_the_fixed_remote_error()
	{
		_fixture.SkipUnlessAvailable();
		CookieJar jar = new();
		await StartAsync();

		var providerReturn = await WalkToProviderReturnAsync(jar, NewSubject(), NewEmail(), Landing);
		// A state the scheme cannot unprotect: the provider's leg failed.
		using var callback = await SendAsync(jar, HttpMethod.Get, Regex.Replace(providerReturn, "state=[^&]+", "state=tampered"));
		using var page = await SendAsync(jar, HttpMethod.Get, LocationOf(callback));
		// The page renders its own fixed text whatever the query carries.
		using var forged = await SendAsync(jar, HttpMethod.Get, "/Account/ExternalLogin?RemoteError=Call%20this%20number");

		foreach (var response in new[] { page, forged })
		{
			response.StatusCode.ShouldBe(HttpStatusCode.OK);
			var html = await response.Content.ReadAsStringAsync(Cancellation);
			html.ShouldContain("The sign-in provider did not complete the sign-in.");
			html.ShouldNotContain("Call this number");
			html.ShouldContain("href=\"/Account/Login\"");
		}
	}

	[Fact]
	protected async Task Registration_creates_a_passwordless_user_adds_the_login_and_sends_a_confirmation_link()
	{
		_fixture.SkipUnlessAvailable();
		var subject = NewSubject();
		var email = NewEmail();
		CookieJar jar = new();
		await StartAsync();

		var (pageUrl, form) = await RegistrationFormAsync(jar, subject, email);
		form.ShouldContain(email, customMessage: "the form shows the provider's email");
		ReadOnlyEmail().IsMatch(form).ShouldBeTrue("the email is shown read-only");
		using var posted = await PostRegistrationAsync(jar, pageUrl, form, email);

		LocationOf(posted).ShouldBe(Landing);
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByLoginAsync(FakeRemote.Scheme, subject)).ShouldNotBeNull();
		user.Email.ShouldBe(email);
		(await userManager.HasPasswordAsync(user)).ShouldBeFalse();
		(await userManager.IsEmailConfirmedAsync(user)).ShouldBeFalse();
		var identity = Ticket(IdentityConstants.ApplicationScheme, posted).ShouldNotBeNull();
		identity.Principal.FindFirstValue(ClaimTypes.NameIdentifier).ShouldBe(user.Id.ToString());
		identity.Principal.FindFirstValue(ClaimTypes.AuthenticationMethod).ShouldBe(FakeRemote.Scheme);
		Deletes(posted, IdentityConstants.ExternalScheme).ShouldBeTrue();

		var sent = _emails.Links.ShouldHaveSingleItem();
		sent.Email.ShouldBe(email);
		sent.Link.ShouldStartWith($"{ConfirmationLink}{user.Id}&code=");
		var code = QueryHelpers.ParseQuery(new Uri(sent.Link).Query)["code"].ToString();
		(await userManager.ConfirmEmailAsync(user, Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code))))
			.Succeeded.ShouldBeTrue("the link confirms the new account");
	}

	[Fact]
	protected async Task A_malformed_email_renders_in_place_and_creates_nothing()
	{
		_fixture.SkipUnlessAvailable();
		var subject = NewSubject();
		CookieJar jar = new();
		await StartAsync();

		// The parse still runs on the provider's (vouched-for) value.
		var (_, page) = await RegistrationFormAsync(jar, subject, "not-an-email");

		page.ShouldContain(UnverifiedEmailMessage);
		HiddenValue().IsMatch(page).ShouldBeFalse("no registration form renders");
		(await _fixture.CreateUserManager().FindByLoginAsync(FakeRemote.Scheme, subject)).ShouldBeNull();
		_emails.Links.ShouldBeEmpty();
	}

	[Theory]
	[InlineData(null)]
	[InlineData("false")]
	protected async Task A_registration_without_a_verified_provider_email_creates_nothing(string? emailVerified)
	{
		_fixture.SkipUnlessAvailable();
		var subject = NewSubject();
		var email = NewEmail();
		CookieJar jar = new();
		await StartAsync();

		var (_, page) = await RegistrationFormAsync(jar, subject, email, emailVerified);

		page.ShouldContain(UnverifiedEmailMessage);
		HiddenValue().IsMatch(page).ShouldBeFalse("no registration form renders");
		var userManager = _fixture.CreateUserManager();
		(await userManager.FindByLoginAsync(FakeRemote.Scheme, subject)).ShouldBeNull();
		(await userManager.FindByEmailAsync(email)).ShouldBeNull();
		_emails.Links.ShouldBeEmpty();
	}

	// Design: the posted value is ignored, never compared -- the account is created under the provider's email.
	[Fact]
	protected async Task A_registration_whose_posted_email_was_tampered_uses_the_provider_email()
	{
		_fixture.SkipUnlessAvailable();
		var subject = NewSubject();
		var providerEmail = NewEmail();
		var tampered = NewEmail();
		CookieJar jar = new();
		await StartAsync();

		var (pageUrl, form) = await RegistrationFormAsync(jar, subject, providerEmail);
		using var posted = await PostRegistrationAsync(jar, pageUrl, form, tampered);

		LocationOf(posted).ShouldBe(Landing);
		var userManager = _fixture.CreateUserManager();
		(await userManager.FindByLoginAsync(FakeRemote.Scheme, subject)).ShouldNotBeNull().Email.ShouldBe(providerEmail);
		(await userManager.FindByEmailAsync(tampered)).ShouldBeNull();
		_emails.Links.ShouldHaveSingleItem().Email.ShouldBe(providerEmail);
	}

	// The decision is the id token's, by ordinal claim name, into the ticket's protected properties: a claim spelled like
	// an email or its flag, which a case-insensitive claim lookup would find, never decides what registers.
	[Theory]
	[MemberData(nameof(IdTokenVariants.Payloads), MemberType = typeof(IdTokenVariants))]
	protected async Task A_token_claim_spelled_like_the_email_or_its_flag_never_decides_the_registration(string payload,
		bool registers)
	{
		_fixture.SkipUnlessAvailable();
		var subject = NewSubject();
		var vouched = NewEmail();
		var victim = NewEmail();
		CookieJar jar = new();
		await StartAsync();

		var (pageUrl, form) = await RegistrationFormAsync(jar, subject, vouched,
			payload: IdTokenVariants.Fill(payload, vouched, victim));
		form.ShouldNotContain(victim);
		var userManager = _fixture.CreateUserManager();
		if (registers)
		{
			form.ShouldContain(vouched);
			using var posted = await PostRegistrationAsync(jar, pageUrl, form, victim);
			LocationOf(posted).ShouldBe(Landing);
			(await userManager.FindByLoginAsync(FakeRemote.Scheme, subject)).ShouldNotBeNull().Email.ShouldBe(vouched);
			_emails.Links.ShouldHaveSingleItem().Email.ShouldBe(vouched);
		}
		else
		{
			form.ShouldContain(UnverifiedEmailMessage);
			HiddenValue().IsMatch(form).ShouldBeFalse("no registration form renders");
			(await userManager.FindByLoginAsync(FakeRemote.Scheme, subject)).ShouldBeNull();
			(await userManager.FindByEmailAsync(vouched)).ShouldBeNull();
			_emails.Links.ShouldBeEmpty();
		}
		(await userManager.FindByEmailAsync(victim)).ShouldBeNull();
	}

	// Design: the external cookie no longer vouches by the post (here another, unverified login replaced it after a
	// verified render). The refusal renders in place; the framework's 400 for an unrendered form never answers.
	[Fact]
	protected async Task An_unverified_registration_post_renders_the_refusal_in_place_and_creates_nothing()
	{
		_fixture.SkipUnlessAvailable();
		var subject = NewSubject();
		var email = NewEmail();
		CookieJar jar = new();
		await StartAsync();

		var (pageUrl, form) = await RegistrationFormAsync(jar, NewSubject(), NewEmail());
		using var unverified = await WalkToCallbackAsync(jar, subject, email, Landing, emailVerified: "false");
		using var posted = await PostRegistrationAsync(jar, pageUrl, form, email);

		posted.StatusCode.ShouldBe(HttpStatusCode.OK);
		(await posted.Content.ReadAsStringAsync(Cancellation)).ShouldContain(UnverifiedEmailMessage);
		var userManager = _fixture.CreateUserManager();
		(await userManager.FindByLoginAsync(FakeRemote.Scheme, subject)).ShouldBeNull();
		(await userManager.FindByEmailAsync(email)).ShouldBeNull();
		Ticket(IdentityConstants.ApplicationScheme, posted).ShouldBeNull();
		Deletes(posted, IdentityConstants.ExternalScheme).ShouldBeTrue();
		_emails.Links.ShouldBeEmpty();
	}

	[Fact]
	protected async Task A_login_add_failure_after_create_leaves_no_user()
	{
		_fixture.SkipUnlessAvailable();
		var subject = NewSubject();
		var email = NewEmail();
		CookieJar jar = new();
		await StartAsync();

		var (pageUrl, form) = await RegistrationFormAsync(jar, subject, email);
		// Another account takes the same (provider, key) between the render and the post: the create succeeds and
		// the add answers LoginAlreadyAssociated.
		var other = await SeedWithLoginAsync(subject);
		using var posted = await PostRegistrationAsync(jar, pageUrl, form, email);

		posted.StatusCode.ShouldBe(HttpStatusCode.OK);
		(await posted.Content.ReadAsStringAsync(Cancellation)).ShouldContain(new IdentityErrorDescriber().LoginAlreadyAssociated().Description);
		var userManager = _fixture.CreateUserManager();
		(await userManager.FindByEmailAsync(email)).ShouldBeNull("the new user is erased");
		(await userManager.FindByLoginAsync(FakeRemote.Scheme, subject)).ShouldNotBeNull().Id.ShouldBe(other.Id);
		Ticket(IdentityConstants.ApplicationScheme, posted).ShouldBeNull();
		_emails.Links.ShouldBeEmpty();
	}

	// RC3's GetExternalLoginInfoAsync takes the provider key from the first ClaimTypes.NameIdentifier, matched ignoring
	// case once the external cookie round-trips, ahead of sub: a token claim spelled like it never names the login.
	[Theory]
	[MemberData(nameof(IdTokenVariants.ForgedNameIdentifiers), MemberType = typeof(IdTokenVariants))]
	protected async Task A_forged_name_identifier_never_signs_in_under_its_value(string forgedType)
	{
		_fixture.SkipUnlessAvailable();
		var victimSubject = NewSubject();
		await SeedWithLoginAsync(victimSubject);
		var subject = NewSubject();
		var user = await SeedWithLoginAsync(subject);
		CookieJar jar = new();
		await StartAsync();

		using var callback = await WalkToCallbackAsync(jar, subject, user.Email!, Landing,
			payload: $$"""{"{{forgedType}}":"{{victimSubject}}","email":"{{user.Email}}","email_verified":true}""");
		using var page = await SendAsync(jar, HttpMethod.Get, LocationOf(callback));

		LocationOf(page).ShouldBe(Landing);
		Ticket(IdentityConstants.ApplicationScheme, page).ShouldNotBeNull()
			.Principal.FindFirstValue(ClaimTypes.NameIdentifier).ShouldBe(user.Id.ToString(), "the login is sub's, never the forged value's");
	}

	[Theory]
	[MemberData(nameof(IdTokenVariants.ForgedNameIdentifiers), MemberType = typeof(IdTokenVariants))]
	protected async Task A_forged_name_identifier_never_links_its_value(string forgedType)
	{
		_fixture.SkipUnlessAvailable();
		var subject = NewSubject();
		var user = await SeedWithLoginAsync(subject);
		CookieJar jar = new();
		await StartAsync();
		using var callback = await WalkToCallbackAsync(jar, subject, user.Email!, Landing);
		using var signedIn = await SendAsync(jar, HttpMethod.Get, LocationOf(callback));
		LocationOf(signedIn).ShouldBe(Landing);

		var linkedSubject = NewSubject();
		var forged = NewSubject();
		var linked = await LinkAsync(jar, linkedSubject, $$"""{"{{forgedType}}":"{{forged}}"}""");

		linked.ShouldBe("/Account/Manage/ExternalLogins?status=external-login-added");
		var userManager = _fixture.CreateUserManager();
		(await userManager.FindByLoginAsync(FakeRemote.Scheme, linkedSubject)).ShouldNotBeNull().Id.ShouldBe(user.Id);
		(await userManager.FindByLoginAsync(FakeRemote.Scheme, forged)).ShouldBeNull("the forged value is never linked");
	}

	[Fact]
	protected async Task A_token_without_a_sub_fails_to_the_fixed_remote_error()
	{
		_fixture.SkipUnlessAvailable();
		var victimSubject = NewSubject();
		await SeedWithLoginAsync(victimSubject);
		CookieJar jar = new();
		await StartAsync();

		var providerReturn = await WalkToProviderReturnAsync(jar, null, NewEmail(), Landing,
			payload: $$"""{"{{ClaimTypes.NameIdentifier}}":"{{victimSubject}}","email":"{{NewEmail()}}","email_verified":true}""");
		using var callback = await SendAsync(jar, HttpMethod.Get, providerReturn);

		LocationOf(callback).ShouldBe(
			"/Account/ExternalLogin?RemoteError=The%20sign-in%20provider%20did%20not%20complete%20the%20sign-in.");
		Ticket(IdentityConstants.ExternalScheme, callback).ShouldBeNull();
		jar.Has(CookieName(IdentityConstants.ExternalScheme)).ShouldBeFalse();
	}

	static string NewSubject() =>
		$"fake-{Guid.NewGuid():N}";

	static string NewEmail() =>
		$"callback-{Guid.NewGuid():N}@example.com";

	async Task<NorseUser> SeedWithLoginAsync(string subject)
	{
		var seeded = await _fixture.SeedUserAsync(NewEmail());
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		(await userManager.AddLoginAsync(user, new(FakeRemote.Scheme, subject, FakeRemote.DisplayName))).Succeeded.ShouldBeTrue();
		return user;
	}

	/// <summary>Enrolls an authenticator and turns two-factor on, answering the key the app would scan.</summary>
	async Task<string> EnableTwoFactorAsync(Guid userId)
	{
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(userId.ToString())).ShouldNotBeNull();
		(await userManager.ResetAuthenticatorKeyAsync(user)).Succeeded.ShouldBeTrue();
		(await userManager.SetTwoFactorEnabledAsync(user, true)).Succeeded.ShouldBeTrue();
		return (await userManager.GetAuthenticatorKeyAsync(user)).ShouldNotBeNull();
	}

	async Task StartAsync()
	{
		var builder = WebApplication.CreateSlimBuilder();
		builder.WebHost.UseTestServer();
		builder.Logging.ClearProviders();
		var services = builder.Services;
		services
			.AddRouting()
			.AddAntiforgery()
			.AddHttpContextAccessor()
			.AddAuthorization(options =>
			{
				options.AddPolicy(AuthNPolicies.Account, AuthNPolicies.ConfigureAccount);
				// The link start's freshness is FreshnessSuite's to prove over Midgard's real requirement; this host, whose
				// caller has just signed in, stands the policy in so the link it walks gets past the gate.
				options.AddPolicy(NorsePolicies.RecentAuthentication, static policy => policy.RequireAuthenticatedUser());
			})
			.AddDataProtection().UseEphemeralDataProtectionProvider();
		services.AddRazorComponents();
		services.AddFluentUIComponents();
		var authentication = services.AddAuthentication(IdentityConstants.ApplicationScheme);
		authentication.AddIdentityCookies();
		authentication.AddFakeRemote();

		// The real managers and erasure, from one fixture scope per request; the sign-in manager over this host.
		services
			.AddScoped(_ => new FixtureScope(_fixture.CreateOwnedScope()))
			.AddScoped(static sp => sp.GetRequiredService<FixtureScope>().Get<UserManager<NorseUser>>())
			.AddScoped(static sp => sp.GetRequiredService<FixtureScope>().Get<ErasureService>())
			.AddScoped(static sp =>
			{
				var fixtureScope = sp.GetRequiredService<FixtureScope>();
				return ActivatorUtilities.CreateInstance<NorseSignInManager>(sp,
					fixtureScope.Get<UserManager<NorseUser>>(),
					fixtureScope.Get<IUserClaimsPrincipalFactory<NorseUser>>(),
					fixtureScope.Get<IOptions<IdentityOptions>>(),
					fixtureScope.Get<IUserConfirmation<NorseUser>>(),
					fixtureScope.Get<IPasskeyHandler<NorseUser>>(),
					fixtureScope.Get<IOptions<IdentityPasskeyOptions>>(),
					fixtureScope.Get<IPasskeyChallengeLedger>(),
					fixtureScope.Get<ReauthMarkers>());
			})
			.AddScoped<SignInManager<NorseUser>>(static sp => sp.GetRequiredService<NorseSignInManager>())
			.AddScoped<ISecurityStampValidator, SecurityStampValidator<NorseUser>>()
			.AddScoped<DeferredCompletion>()
			.AddSingleton(Substitute.For<IDeferredSignIn>())
			.AddSingleton<IEmailSender<NorseUser>>(_emails);

		_app = builder.Build();
		_app.UseRouting();
		_app.UseAuthentication();
		_app.UseAuthorization();
		_app.UseAntiforgery();
		_app.MapNorseExternalLoginEndpoints();
		_app.MapFakeProvider();
		// The second-factor page is Heimdall's; this stands in for its handler's completion over the token.
		_app.MapGet(TestRedeemPath, static async (HttpContext context, string challenge, string code) =>
		{
			var result = await context.RequestServices.GetRequiredService<NorseSignInManager>()
				.TwoFactorChallengeSignInAsync(challenge, code, rememberClient: false);
			return result.Result.Succeeded ?
				Results.Text(result.ReturnUrl) :
				Results.StatusCode(StatusCodes.Status401Unauthorized);
		});
		_app.MapRazorComponents<CallbackTestRoot>().AddAdditionalAssemblies(typeof(ExternalLoginCallback).Assembly);
		await _app.StartAsync(Cancellation);
		_client = _app.GetTestClient();
	}

	/// <summary>
	///     Start, then the fake provider: answers the provider's redirect back to the scheme's callback path. The provider
	///     asserts <paramref name="emailVerified" /> as the id token's <c>email_verified</c>; null asserts nothing. A
	///     <paramref name="payload" /> replaces the rest of the id token payload; the token's <c>sub</c> is
	///     <paramref name="subject" />, and a null one leaves the token without a <c>sub</c>.
	/// </summary>
	async Task<string> WalkToProviderReturnAsync(CookieJar jar, string? subject, string email, string returnUrl,
		string? emailVerified = "true", string? payload = null)
	{
		using var start = await SendAsync(jar, HttpMethod.Get,
			$"/Account/PerformExternalLogin?provider={FakeRemote.Scheme}&returnUrl={Uri.EscapeDataString(returnUrl)}");
		return await ProviderReturnAsync(jar, start, subject, payload ?? PayloadOf(email, emailVerified));
	}

	/// <summary>Follows a start's challenge through the fake provider: answers its redirect back to the callback path.</summary>
	async Task<string> ProviderReturnAsync(CookieJar jar, HttpResponseMessage start, string? subject, string payload)
	{
		var authorize = LocationOf(start);
		authorize.ShouldStartWith(FakeRemote.AuthorizePath);
		jar.Has(name => name.StartsWith(".AspNetCore.Correlation.", StringComparison.Ordinal)).ShouldBeTrue();

		var token = subject is null ? payload : IdTokenVariants.WithSubject(payload, subject);
		using var provider = await SendAsync(jar, HttpMethod.Get, $"{authorize}&payload={Uri.EscapeDataString(token)}");
		var providerReturn = LocationOf(provider);
		providerReturn.ShouldStartWith(FakeRemote.CallbackPath);
		return providerReturn;
	}

	/// <summary>
	///     The link round trip for the signed-in caller in <paramref name="jar" />: the link start, the fake provider with
	///     <paramref name="payload" /> under <paramref name="subject" />, the scheme's callback and the link callback.
	///     Answers the link callback's redirect.
	/// </summary>
	async Task<string> LinkAsync(CookieJar jar, string subject, string payload)
	{
		using var start = await SendAsync(jar, HttpMethod.Get, $"/Account/Manage/LinkExternalLogin?provider={FakeRemote.Scheme}");
		var providerReturn = await ProviderReturnAsync(jar, start, subject, payload);
		using var callback = await SendAsync(jar, HttpMethod.Get, providerReturn);
		LocationOf(callback).ShouldBe("/Account/Manage/LinkExternalLoginCallback");
		using var linked = await SendAsync(jar, HttpMethod.Get, LocationOf(callback));
		return LocationOf(linked);
	}

	/// <summary>The whole start leg: answers the scheme's redirect to the callback page, external cookie in the jar.</summary>
	async Task<HttpResponseMessage> WalkToCallbackAsync(CookieJar jar, string subject, string email, string returnUrl,
		string? emailVerified = "true", string? payload = null)
	{
		var providerReturn = await WalkToProviderReturnAsync(jar, subject, email, returnUrl, emailVerified, payload);
		var callback = await SendAsync(jar, HttpMethod.Get, providerReturn);
		LocationOf(callback).ShouldStartWith("/Account/ExternalLogin?");
		jar.Has(CookieName(IdentityConstants.ExternalScheme)).ShouldBeTrue();
		return callback;
	}

	/// <summary>
	///     Walks a login no account has to the page: the registration form when the provider vouched for the email,
	///     otherwise the in-place refusal.
	/// </summary>
	async Task<(string PageUrl, string Form)> RegistrationFormAsync(CookieJar jar, string subject, string email,
		string? emailVerified = "true", string? payload = null)
	{
		using var callback = await WalkToCallbackAsync(jar, subject, email, Landing, emailVerified, payload);
		var pageUrl = LocationOf(callback);
		using var page = await SendAsync(jar, HttpMethod.Get, pageUrl);
		page.StatusCode.ShouldBe(HttpStatusCode.OK);
		return (pageUrl, await page.Content.ReadAsStringAsync(Cancellation));
	}

	/// <summary>Posts the form, with <paramref name="postedEmail" /> as a tampering client would add it; the page reads none.</summary>
	Task<HttpResponseMessage> PostRegistrationAsync(CookieJar jar, string pageUrl, string form, string postedEmail)
	{
		var token = HiddenValue().Match(form);
		token.Success.ShouldBeTrue("the form carries an antiforgery token");
		var handler = HandlerValue().Match(form);
		handler.Success.ShouldBeTrue("the form names its handler");
		FormUrlEncodedContent content = new(
		[
			new("_handler", WebUtility.HtmlDecode(handler.Groups[1].Value)),
			new("__RequestVerificationToken", WebUtility.HtmlDecode(token.Groups[1].Value)),
			new("Input.Email", postedEmail)
		]);
		return SendAsync(jar, HttpMethod.Post, pageUrl, content);
	}

	/// <summary>An id token payload with the <c>email</c> and, unless null, the string <c>email_verified</c>.</summary>
	static string PayloadOf(string email, string? emailVerified) =>
		emailVerified is null ?
			$$"""{"email":"{{email}}"}""" :
			$$"""{"email":"{{email}}","email_verified":"{{emailVerified}}"}""";

	async Task<HttpResponseMessage> SendAsync(CookieJar jar, HttpMethod method, string url, HttpContent? content = null)
	{
		using HttpRequestMessage request = new(method, new Uri(url, UriKind.Relative)) { Content = content };
		request.Headers.Add("Sec-Fetch-Site", "same-origin");
		if (jar.Header is { } cookie)
			request.Headers.Add("Cookie", cookie);
		var response = await _client!.SendAsync(request, Cancellation);
		jar.Absorb(response);
		return response;
	}

	/// <summary>
	///     The redirect's target, as a root-relative URL. Blazor's static-SSR navigation answers an absolute
	///     <c>Location</c>, so an absolute one is folded only when it names the test server's own origin; any other origin
	///     comes back whole, and no local assertion can match it.
	/// </summary>
	static string LocationOf(HttpResponseMessage response)
	{
		response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
		var location = response.Headers.Location.ShouldNotBeNull();
		return location.IsAbsoluteUri && location.GetLeftPart(UriPartial.Authority) == "http://localhost" ?
			location.PathAndQuery :
			location.OriginalString;
	}

	static string ReplaceReturnUrl(string pageUrl, string returnUrl)
	{
		var query = QueryHelpers.ParseQuery(pageUrl[pageUrl.IndexOf('?', StringComparison.Ordinal)..]);
		return QueryHelpers.AddQueryString("/Account/ExternalLogin", new Dictionary<string, string?>
		{
			["Action"] = query["Action"],
			["ReturnUrl"] = returnUrl
		});
	}

	string CookieName(string scheme) =>
		_app!.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(scheme).Cookie.Name!;

	/// <summary>The ticket <paramref name="response" /> wrote for <paramref name="scheme" />, or null when it wrote none.</summary>
	AuthenticationTicket? Ticket(string scheme, HttpResponseMessage response)
	{
		var options = _app!.Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(scheme);
		var value = CookieJar.SetCookies(response)
			.Select(CookieJar.Parse)
			.Where(cookie => cookie.Name == options.Cookie.Name && !cookie.Deleted)
			.Select(static cookie => cookie.Value)
			.SingleOrDefault();
		return value is null ?
			null :
			options.TicketDataFormat.Unprotect(value);
	}

	bool Deletes(HttpResponseMessage response, string scheme) =>
		CookieJar.SetCookies(response).Select(CookieJar.Parse)
			.Any(cookie => cookie.Name == CookieName(scheme) && cookie.Deleted);

	[GeneratedRegex("name=\"__RequestVerificationToken\" value=\"([^\"]+)\"")]
	private static partial Regex HiddenValue();

	[GeneratedRegex("name=\"_handler\" value=\"([^\"]+)\"")]
	private static partial Regex HandlerValue();

	[GeneratedRegex("<input[^>]*\\breadonly\\b[^>]*>|<fluent-text-input[^>]*\\breadonly\\b[^>]*>", RegexOptions.IgnoreCase)]
	private static partial Regex ReadOnlyEmail();

	/// <summary>A fixture scope the host's request scope owns, so each request gets fresh managers over one context.</summary>
	sealed class FixtureScope(IServiceScope scope) : IDisposable
	{
		public T Get<T>() where T : notnull =>
			scope.ServiceProvider.GetRequiredService<T>();

		public void Dispose() =>
			scope.Dispose();
	}

	/// <summary>Every confirmation link sent.</summary>
	sealed class CapturingEmailSender : IEmailSender<NorseUser>
	{
		public ConcurrentQueue<(string Email, string Link)> Links { get; } = new();

		public Task SendConfirmationLinkAsync(NorseUser user, string email, string confirmationLink)
		{
			Links.Enqueue((email, confirmationLink));
			return Task.CompletedTask;
		}

		public Task SendPasswordResetLinkAsync(NorseUser user, string email, string resetLink) =>
			Task.CompletedTask;

		public Task SendPasswordResetCodeAsync(NorseUser user, string email, string resetCode) =>
			Task.CompletedTask;
	}

	/// <summary>
	///     A hand-driven cookie jar: the test server keeps none, and the correlation cookie is <c>Secure</c> on a plain-HTTP
	///     test origin, so attributes are ignored and every cookie is sent on every request.
	/// </summary>
	sealed class CookieJar
	{
		readonly Dictionary<string, string> _cookies = new(StringComparer.Ordinal);

		public string? Header =>
			_cookies.Count == 0 ?
				null :
				string.Join("; ", _cookies.Select(static cookie => $"{cookie.Key}={cookie.Value}"));

		public bool Has(string name) =>
			_cookies.ContainsKey(name);

		public bool Has(Func<string, bool> match) =>
			_cookies.Keys.Any(match);

		public void Remove(string name) =>
			_cookies.Remove(name);

		public void Absorb(HttpResponseMessage response)
		{
			foreach (var cookie in SetCookies(response).Select(Parse))
				if (cookie.Deleted)
					_cookies.Remove(cookie.Name);
				else
					_cookies[cookie.Name] = cookie.Value;
		}

		public static IEnumerable<string> SetCookies(HttpResponseMessage response) =>
			response.Headers.TryGetValues("Set-Cookie", out var values) ?
				values :
				[];

		public static (string Name, string Value, bool Deleted) Parse(string setCookie)
		{
			var pair = setCookie.Split(';', 2)[0];
			var separator = pair.IndexOf('=', StringComparison.Ordinal);
			var value = pair[(separator + 1)..];
			var deleted = value.Length == 0
				|| setCookie.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase);
			return (pair[..separator], value, deleted);
		}
	}
}
