using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Norse.Abstractions.Components.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.OpenIddict;
using Norse.Primitives;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     The production authorize endpoint (2026-10-29 OpenIddict spec §5.2, §5.7, §10.3, §10.4, §10.9; plan Task 4.4 and
///     Review Focus 1–3, 5), once per provider, over <see cref="AuthorizeHost" />: code + PKCE, <c>prompt</c> and
///     <c>max_age</c>, the <c>norse_reauth</c> re-challenge and its binding, and the ad-hoc authorization. Halting gate H6 is
///     the first fact. The code's exchange is <see cref="TokenEndpointSuite" />'s.
/// </summary>
/// <remarks>
///     Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///     records: xUnit discovers them on each <see langword="sealed" /> provider class.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class AuthorizeEndpointSuite(IdentityFixture fixture)
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <summary>The parameters a marker is bound to, each changed on re-entry.</summary>
	public static TheoryData<string> BoundParameters =>
		[Parameters.CodeChallenge, Parameters.State, Parameters.Nonce, Parameters.Scope, Parameters.ClientId, Parameters.RedirectUri];

	/// <summary>Values no reading of <c>max_age</c> as a non-negative integer accepts.</summary>
	public static TheoryData<string> MalformedMaxAges => ["abc", "-1", "", "1.5", " 5", "5 ", "+5", "1e3", "99999999999999999999"];

	/// <summary>The singular parameters a repeat of which is refused before any marker exists.</summary>
	public static TheoryData<string> SingularParameters =>
		[Parameters.State, Parameters.Nonce, Parameters.Scope, Parameters.Prompt, Parameters.MaxAge, Parameters.CodeChallenge];

	/// <summary>Cookie <c>auth_time</c> claims that read as stale: none, unparseable, ambiguous, in the future.</summary>
	public static TheoryData<string> StaleAuthTimes => ["missing", "unparseable", "fractional", "signed", "two", "future"];

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	// H6: OpenIddict 8 hands the unknown norse_reauth parameter to the passthrough endpoint, unrejected and unstripped.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Premise_the_marker_parameter_reaches_the_passthrough()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var value = $"premise-{Guid.NewGuid():N}";

		using var response = await host.AuthorizeAsync(AuthorizeRequest.Create().Adding("norse_reauth", value));

		host.PassedMarkers.ShouldBe([value],
			$"the endpoint was handed the marker ({response.StatusCode} {response.Headers.Location} {await response.Content.ReadAsStringAsync(Cancellation)})");
		Answer.Of(response, host).Kind.ShouldBe(AnswerKind.Challenge);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_fresh_cookie_is_issued_a_code()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.SignInAsync(user);
		var request = AuthorizeRequest.Create();

		using var first = await host.AuthorizeAsync(request, cookie);

		var answer = Answer.Of(first, host);
		answer.Kind.ShouldBe(AnswerKind.Code);
		answer.Location!.ShouldStartWith(AuthorizeHost.RedirectUri.AbsoluteUri + "?");
		answer.Code.ShouldNotBeNullOrEmpty();
		answer.State.ShouldBe(request[Parameters.State]);
		var grant = (await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem();
		grant.Type.ShouldBe(AuthorizationTypes.AdHoc);
		grant.Status.ShouldBe(Statuses.Valid);
		grant.TokenTypes.ShouldBe([TokenTypeIdentifiers.Private.AuthorizationCode]);

		using var second = await host.AuthorizeAsync(AuthorizeRequest.Create(), cookie);

		Answer.Of(second, host).Kind.ShouldBe(AnswerKind.Code);
		var grants = await host.ReadGrantsAsync(user.Id);
		grants.Count.ShouldBe(2, "every authorize request creates its own ad-hoc authorization");
		grants.ShouldAllBe(static row => row.Type == AuthorizationTypes.AdHoc && row.Status == Statuses.Valid);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task The_anonymous_principal_is_challenged_to_login()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var request = AuthorizeRequest.Create();

		using var response = await host.AuthorizeAsync(request);

		var answer = Answer.Of(response, host);
		answer.Kind.ShouldBe(AnswerKind.Challenge);
		var reentry = Query(answer.ReturnUrl!);
		answer.ReturnUrl!.ShouldStartWith("/connect/authorize?");
		reentry["norse_reauth"].Count.ShouldBe(1);
		foreach (var (name, value) in request.Pairs)
			reentry[name].ToString().ShouldBe(value);
		var marker = Marker(host, answer.ReturnUrl!);
		marker.UserId.ShouldBeNull("an anonymous challenge names no user");
		marker.ExpiresAt.ShouldBe(host.Clock.GetUtcNow() + ReauthMarkers.Lifetime);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_request_without_a_code_challenge_is_refused()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var request = AuthorizeRequest.Create().Without(Parameters.CodeChallenge).Without(Parameters.CodeChallengeMethod);

		using var response = await host.AuthorizeAsync(request, await host.SignInAsync(await AuthorizeHost.SeedUserAsync(fixture)));

		await ShouldBeRefusedAsync(response, Errors.InvalidRequest);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_plain_code_challenge_is_refused()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var request = AuthorizeRequest.Create().With(Parameters.CodeChallengeMethod, CodeChallengeMethods.Plain);

		using var response = await host.AuthorizeAsync(request, await host.SignInAsync(await AuthorizeHost.SeedUserAsync(fixture)));

		await ShouldBeRefusedAsync(response, Errors.InvalidRequest);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_mismatched_redirect_uri_is_never_redirected_to()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);

		using var response = await host.AuthorizeAsync(
			AuthorizeRequest.Create().With(Parameters.RedirectUri, "http://127.0.0.1/elsewhere"));

		response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
		response.Headers.Location.ShouldBeNull();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_unknown_client_is_never_redirected_to()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);

		using var response = await host.AuthorizeAsync(AuthorizeRequest.Create($"unknown-{Guid.NewGuid():N}"));

		response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
		response.Headers.Location.ShouldBeNull();
	}

	// Spec §5.7: the optional members are suppressed on the redirect (the endpoint's own refusal) and on the page
	// (OpenIddict's, which never redirects a request its validation rejected) alike.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Authorize_errors_carry_no_description_and_no_uri()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);

		using var redirected = await host.AuthorizeAsync(AuthorizeRequest.Create().Adding(Parameters.MaxAge, "soon"));
		using var page = await host.AuthorizeAsync(
			AuthorizeRequest.Create().With(Parameters.CodeChallengeMethod, CodeChallengeMethods.Plain));

		var query = Query(redirected.Headers.Location.ShouldNotBeNull().OriginalString);
		query[Parameters.Error].ToString().ShouldBe(Errors.InvalidRequest);
		query.ShouldNotContainKey(Parameters.ErrorDescription);
		query.ShouldNotContainKey(Parameters.ErrorUri);
		var body = await ShouldBeRefusedAsync(page, Errors.InvalidRequest);
		body.ShouldNotContain(Parameters.ErrorDescription);
		body.ShouldNotContain(Parameters.ErrorUri);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Prompt_none_answers_login_required_with_state_when_anonymous()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var request = AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.None);

		using var response = await host.AuthorizeAsync(request);

		Answer.Of(response, host).ShouldBeError(Errors.LoginRequired, request[Parameters.State]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Prompt_none_answers_login_required_with_state_when_stale()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var request = AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.None);

		using var response = await host.AuthorizeAsync(request, await CraftCookieAsync(host, user, authTime: null));

		Answer.Of(response, host).ShouldBeError(Errors.LoginRequired, request[Parameters.State]);
	}

	// Final I1: the cookie is not the user. After authenticating it the endpoint re-reads the user, so an erased user's
	// surviving cookie (inside its security-stamp validation interval) is no principal: challenged, or login_required under
	// prompt=none, and no authorization or code row names the erased subject.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[InlineData(false)]
	[InlineData(true)]
	protected async Task An_erased_users_surviving_cookie_mints_nothing(bool promptNone)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.SignInAsync(user);
		await using (var scope = host.Services.CreateAsyncScope())
			(await scope.ServiceProvider.GetRequiredService<ErasureService>().ShredAsync(user.Id, Cancellation))
				.TryGetValue(out Success<ErasureReceipt> _).ShouldBeTrue();
		var request = promptNone ? AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.None) : AuthorizeRequest.Create();

		using var response = await host.AuthorizeAsync(request, cookie);

		ShouldBeNoPrincipal(host, response, request, promptNone);
		(await host.ReadGrantsAsync(user.Id)).ShouldBeEmpty("no authorization names the erased subject");
		(await host.CountTokensAsync(user.Id)).ShouldBe(0, "no code names the erased subject");
	}

	// Final I1: a cookie whose stamp the user's record no longer carries (a password change elsewhere) is no principal, so a
	// silent sign-in never loops on a code the exchange would refuse.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[InlineData(false)]
	[InlineData(true)]
	protected async Task A_stamp_rotated_cookie_is_challenged_and_never_issued_a_code(bool promptNone)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.SignInAsync(user);
		var userManager = fixture.CreateUserManager();
		(await userManager.UpdateSecurityStampAsync((await userManager.FindByIdAsync(user.Id.ToString())).ShouldNotBeNull()))
			.Succeeded.ShouldBeTrue();
		var request = promptNone ? AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.None) : AuthorizeRequest.Create();

		using var response = await host.AuthorizeAsync(request, cookie);

		ShouldBeNoPrincipal(host, response, request, promptNone);
		(await host.ReadGrantsAsync(user.Id)).ShouldBeEmpty("a stamp-rotated cookie mints no authorization");
	}

	// Final I1 with Buvy's lockout ruling: a lockout is not a reason. A locked-out user's valid cookie is still issued a code.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_locked_out_users_valid_cookie_is_still_issued_a_code()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.SignInAsync(user);
		await host.LockOutByFailedPasswordsAsync(user);

		(await host.IssueCodeAsync(AuthorizeRequest.Create(), cookie)).ShouldNotBeNullOrEmpty();
		(await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem().Status.ShouldBe(Statuses.Valid);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Prompt_none_with_login_is_invalid_request()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var cookie = await host.SignInAsync(await AuthorizeHost.SeedUserAsync(fixture));
		var request = AuthorizeRequest.Create().Adding(Parameters.Prompt, $"{PromptValues.None} {PromptValues.Login}");

		using var response = await host.AuthorizeAsync(request, cookie);

		await ShouldBeRefusedAsync(response, Errors.InvalidRequest);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Prompt_login_challenges_and_re_entry_with_the_marker_is_issued_a_code()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.SignInAsync(user);
		var request = AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.Login);

		using var challenge = await host.AuthorizeAsync(request, cookie);

		var returnUrl = Answer.Of(challenge, host).ShouldBeChallenge();
		Marker(host, returnUrl).UserId.ShouldBe(user.Id, "the challenge names the cookie's user");
		var bound = await host.SignInAsync(user, returnUrl);
		using var reentry = await host.GetAsync(returnUrl, bound);
		var answer = Answer.Of(reentry, host);
		answer.Kind.ShouldBe(AnswerKind.Code);
		answer.State.ShouldBe(request[Parameters.State]);
	}

	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(MalformedMaxAges))]
	protected async Task Malformed_max_age_is_invalid_request(string maxAge)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var request = AuthorizeRequest.Create().Adding(Parameters.MaxAge, maxAge);

		using var response = await host.AuthorizeAsync(request, await host.SignInAsync(await AuthorizeHost.SeedUserAsync(fixture)));

		Answer.Of(response, host).ShouldBeError(Errors.InvalidRequest, request[Parameters.State]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Max_age_zero_with_a_delay_re_enters_once()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.SignInAsync(user);
		var request = AuthorizeRequest.Create().Adding(Parameters.MaxAge, "0");

		using var challenge = await host.AuthorizeAsync(request, cookie);
		var returnUrl = Answer.Of(challenge, host).ShouldBeChallenge();
		var bound = await host.SignInAsync(user, returnUrl);
		host.Clock.Advance(TimeSpan.FromSeconds(30));
		using var reentry = await host.GetAsync(returnUrl, bound);

		Answer.Of(reentry, host).Kind.ShouldBe(AnswerKind.Code, "the satisfied marker satisfies max_age=0, so one challenge in all");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_stale_max_age_challenges_and_a_recent_one_is_issued_a_code()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var cookie = await host.SignInAsync(await AuthorizeHost.SeedUserAsync(fixture));
		host.Clock.Advance(TimeSpan.FromSeconds(120));

		using var stale = await host.AuthorizeAsync(AuthorizeRequest.Create().Adding(Parameters.MaxAge, "119"), cookie);
		using var exact = await host.AuthorizeAsync(AuthorizeRequest.Create().Adding(Parameters.MaxAge, "120"), cookie);

		Answer.Of(stale, host).Kind.ShouldBe(AnswerKind.Challenge);
		Answer.Of(exact, host).Kind.ShouldBe(AnswerKind.Code);
	}

	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(BoundParameters))]
	protected async Task A_re_entry_with_a_changed_parameter_re_challenges(string parameter)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var (returnUrl, bound) = await BoundReentryAsync(host, user);
		var changed = parameter switch
		{
			Parameters.CodeChallenge => AuthorizeRequest.Challenge($"another-verifier-{Guid.NewGuid():N}"),
			Parameters.Scope => Scopes.OpenId,
			Parameters.ClientId => AuthorizeHost.OtherClientId,
			Parameters.RedirectUri => AuthorizeHost.OtherRedirectUri.AbsoluteUri,
			_ => $"changed-{Guid.NewGuid():N}"
		};

		using var reentry = await host.GetAsync(Replace(returnUrl, parameter, changed), bound);

		ShouldReChallenge(host, reentry, returnUrl);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_expired_marker_re_challenges()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var (returnUrl, bound) = await BoundReentryAsync(host, await AuthorizeHost.SeedUserAsync(fixture));
		host.Clock.Advance(ReauthMarkers.Lifetime);

		using var reentry = await host.GetAsync(returnUrl, bound);

		ShouldReChallenge(host, reentry, returnUrl);
	}

	// Condition 4 at the endpoint: a cookie for another user carrying the marker's id, as no sign-in would stamp it.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_marker_issued_to_another_user_re_challenges()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var other = await AuthorizeHost.SeedUserAsync(fixture);
		using var challenge = await host.AuthorizeAsync(AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.Login),
			await host.SignInAsync(user));
		var returnUrl = Answer.Of(challenge, host).ShouldBeChallenge();
		var markerId = Marker(host, returnUrl).MarkerId.ToString("N", CultureInfo.InvariantCulture);

		using var signedIn = await host.GetAsync(returnUrl, await host.SignInAsync(other, returnUrl));
		using var crafted = await host.GetAsync(returnUrl, await CraftCookieAsync(host, other, Now(host), markerId));

		ShouldReChallenge(host, signedIn, returnUrl);
		ShouldReChallenge(host, crafted, returnUrl);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_burned_marker_re_challenges()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var (returnUrl, bound) = await BoundReentryAsync(host, await AuthorizeHost.SeedUserAsync(fixture));
		var marker = Marker(host, returnUrl);

		using var first = await host.GetAsync(returnUrl, bound);
		using var second = await host.GetAsync(returnUrl, bound);

		Answer.Of(first, host).Kind.ShouldBe(AnswerKind.Code);
		ShouldReChallenge(host, second, returnUrl);
		// PF6: the ledger key is the UTF-8 of the prefixed "N" id, which the ledger hashes itself.
		await using var scope = host.Services.CreateAsyncScope();
		(await scope.ServiceProvider.GetRequiredService<IPasskeyChallengeLedger>().TryConsumeAsync(
				Encoding.UTF8.GetBytes("norse_reauth:" + marker.MarkerId.ToString("N", CultureInfo.InvariantCulture)),
				marker.ExpiresAt, Cancellation))
			.ShouldBeFalse("the marker was burned under its prefixed id");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Two_concurrent_re_entries_issue_at_most_one_code()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var (returnUrl, bound) = await BoundReentryAsync(host, await AuthorizeHost.SeedUserAsync(fixture));

		var responses = await Task.WhenAll(host.GetAsync(returnUrl, bound), host.GetAsync(returnUrl, bound));

		try
		{
			responses.Count(response => Answer.Of(response, host).Kind == AnswerKind.Code).ShouldBe(1);
			responses.Count(response => Answer.Of(response, host).Kind == AnswerKind.Challenge).ShouldBe(1);
		}
		finally
		{
			foreach (var response in responses)
				response.Dispose();
		}
	}

	// A frozen clock, never advanced: the marker carries no clock comparison, so each bound sign-in satisfies its own.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Same_second_successive_reauthentications_each_succeed()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.SignInAsync(user);
		var second = host.Clock.GetUtcNow();

		for (var attempt = 0; attempt < 3; attempt++)
		{
			using var challenge = await host.AuthorizeAsync(AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.Login),
				cookie);
			var returnUrl = Answer.Of(challenge, host).ShouldBeChallenge();
			cookie = await host.SignInAsync(user, returnUrl);
			using var reentry = await host.GetAsync(returnUrl, cookie);
			Answer.Of(reentry, host).Kind.ShouldBe(AnswerKind.Code, $"re-authentication {attempt + 1} is satisfied");
		}

		host.Clock.GetUtcNow().ShouldBe(second);
	}

	// §10.4: A and B from separate sign-ins, B two seconds before the challenge, which receives A; re-entry presents B.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Two_pre_existing_cookies()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookieA = await host.SignInAsync(user);
		host.Clock.Advance(TimeSpan.FromSeconds(1));
		var cookieB = await host.SignInAsync(user);
		host.Clock.Advance(TimeSpan.FromSeconds(2));
		var request = AuthorizeRequest.Create().Adding(Parameters.MaxAge, "0");
		using var challenge = await host.AuthorizeAsync(request, cookieA);
		var returnUrl = Answer.Of(challenge, host).ShouldBeChallenge();

		using var reentry = await host.GetAsync(returnUrl, cookieB);
		using var silent = await host.GetAsync(Replace(returnUrl, Parameters.Prompt, PromptValues.None), cookieB);

		ShouldReChallenge(host, reentry, returnUrl);
		Answer.Of(silent, host).ShouldBeError(Errors.LoginRequired, request[Parameters.State]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Anonymous_challenge_with_a_pre_existing_cookie()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var cookie = await host.SignInAsync(await AuthorizeHost.SeedUserAsync(fixture));
		using var challenge = await host.AuthorizeAsync(AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.Login));
		var returnUrl = Answer.Of(challenge, host).ShouldBeChallenge();

		using var reentry = await host.GetAsync(returnUrl, cookie);

		ShouldReChallenge(host, reentry, returnUrl);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Re_entry_with_the_challenged_cookie_re_challenges()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var cookie = await host.SignInAsync(await AuthorizeHost.SeedUserAsync(fixture));
		using var challenge = await host.AuthorizeAsync(AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.Login),
			cookie);
		var returnUrl = Answer.Of(challenge, host).ShouldBeChallenge();

		using var reentry = await host.GetAsync(returnUrl, cookie);

		ShouldReChallenge(host, reentry, returnUrl);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_cookie_bound_to_M_does_not_satisfy_M_prime()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.SignInAsync(user);
		using var challengeM = await host.AuthorizeAsync(AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.Login),
			cookie);
		using var challengeMPrime = await host.AuthorizeAsync(
			AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.Login), cookie);
		var returnUrlM = Answer.Of(challengeM, host).ShouldBeChallenge();
		var returnUrlMPrime = Answer.Of(challengeMPrime, host).ShouldBeChallenge();
		var boundToM = await host.SignInAsync(user, returnUrlM);

		using var reentry = await host.GetAsync(returnUrlMPrime, boundToM);

		ShouldReChallenge(host, reentry, returnUrlMPrime);
	}

	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(StaleAuthTimes))]
	protected async Task A_missing_or_malformed_auth_time_is_stale(string authTime)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var now = Now(host);
		string[]? values = authTime switch
		{
			"missing" => null,
			"unparseable" => ["yesterday"],
			"fractional" => [$"{now}.5"],
			"signed" => [$"+{now}"],
			"two" => [now.ToString(CultureInfo.InvariantCulture), now.ToString(CultureInfo.InvariantCulture)],
			"future" => [(now + 301).ToString(CultureInfo.InvariantCulture)],
			_ => throw new ArgumentOutOfRangeException(nameof(authTime))
		};

		using var stale = await host.AuthorizeAsync(AuthorizeRequest.Create(), await CraftCookieAsync(host, user, values));
		using var fresh = await host.AuthorizeAsync(AuthorizeRequest.Create(),
			await CraftCookieAsync(host, user, [now.ToString(CultureInfo.InvariantCulture)]));

		Answer.Of(stale, host).Kind.ShouldBe(AnswerKind.Challenge, "a stale cookie is never treated as fresh");
		Answer.Of(fresh, host).Kind.ShouldBe(AnswerKind.Code, "the crafted cookie is otherwise a fresh one");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Non_implicit_consent_is_consent_required()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var request = AuthorizeRequest.Create(AuthorizeHost.ExplicitConsentClientId);

		using var response = await host.AuthorizeAsync(request, await host.SignInAsync(user));

		Answer.Of(response, host).ShouldBeError(Errors.ConsentRequired, request[Parameters.State]);
		(await host.ReadGrantsAsync(user.Id)).ShouldBeEmpty();
	}

	// Review Focus 1: the challenge's returnUrl, the landing check and the re-entry all hold under PathBase = /app.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Authorize_reauth_round_trip_under_a_path_base()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture, new PathString("/app"));
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var request = AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.Login);

		using var challenge = await host.AuthorizeAsync(request, await host.SignInAsync(user));

		var answer = Answer.Of(challenge, host);
		answer.Location!.ShouldStartWith("https://localhost/app/Account/Login?");
		var returnUrl = answer.ShouldBeChallenge();
		returnUrl.ShouldStartWith("/app/connect/authorize?");
		var bound = await host.SignInAsync(user, returnUrl);
		using var reentry = await host.GetAsync(returnUrl, bound);
		var issued = Answer.Of(reentry, host);
		issued.Kind.ShouldBe(AnswerKind.Code);
		issued.State.ShouldBe(request[Parameters.State]);
	}

	// Review Focus 2 (T4-7): a POST re-enters as the GET form of the same parameters, under the same hash.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_posted_authorize_request_re_enters_as_a_get_and_is_issued_a_code()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var request = AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.Login);

		using var challenge = await host.AuthorizeAsync(request, await host.SignInAsync(user), post: true);

		var returnUrl = Answer.Of(challenge, host).ShouldBeChallenge();
		var reentry = Query(returnUrl);
		reentry.Keys.ShouldBe([.. request.Pairs.Select(static parameter => parameter.Key), "norse_reauth"], ignoreOrder: true);
		foreach (var (name, value) in request.Pairs)
			reentry[name].ToString().ShouldBe(value);
		Marker(host, returnUrl).TransactionHash.ShouldBe(AuthorizeTransaction.Hash(
			request.Pairs.Select(static parameter => new KeyValuePair<string, StringValues>(parameter.Key, parameter.Value))));
		using var issued = await host.GetAsync(returnUrl, await host.SignInAsync(user, returnUrl));
		var answer = Answer.Of(issued, host);
		answer.Kind.ShouldBe(AnswerKind.Code);
		answer.State.ShouldBe(request[Parameters.State]);
	}

	// Review Focus 3 (T4-6): ReturnUrls.Resolve would drop the re-entry to the root, so the request is refused instead.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_authorize_request_too_long_to_re_enter_is_refused_before_the_challenge()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var request = AuthorizeRequest.Create().Adding("padding", new string('p', ReturnUrls.MaxLength));

		using var response = await host.AuthorizeAsync(request);

		Answer.Of(response, host).ShouldBeError(Errors.InvalidRequest, request[Parameters.State]);
	}

	// Review Focus 5: OpenIddict reads a repeated singular parameter as absent, so the endpoint refuses it. A fresh cookie is
	// presented, so without the refusal every row but code_challenge would be issued a code or challenged instead.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(SingularParameters))]
	protected async Task A_repeated_singular_parameter_is_refused_before_a_marker_is_minted(string parameter)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var cookie = await host.SignInAsync(await AuthorizeHost.SeedUserAsync(fixture));
		var request = AuthorizeRequest.Create();
		var (first, second) = parameter == Parameters.Prompt ? (PromptValues.Login, PromptValues.Login) : ("0", "1");
		request = (request.Pairs.Any(pair => pair.Key == parameter) ? request : request.Adding(parameter, first))
			.Adding(parameter, second);

		using var response = await host.AuthorizeAsync(request, cookie);

		if (parameter == Parameters.CodeChallenge)
		{
			// OpenIddict's own refusal: it reads the repeat as a missing challenge, so the endpoint never runs.
			await ShouldBeRefusedAsync(response, Errors.InvalidRequest);
			host.PassedMarkers.ShouldBeEmpty("OpenIddict refused before the endpoint ran");
			return;
		}

		// The endpoint's refusal: it ran, and redirected invalid_request instead of a code or a challenge.
		host.PassedMarkers.Count.ShouldBe(1, "OpenIddict let the request through to the endpoint");
		var answer = Answer.Of(response, host);
		answer.Kind.ShouldBe(AnswerKind.Error, $"{response.StatusCode} {response.Headers.Location}");
		answer.Location.ShouldNotBeNull("the endpoint's own errors redirect to the client");
		answer.Error.ShouldBe(Errors.InvalidRequest);
	}

	// I1: ASP.NET merges a case-variant spelling and the exact one into one key, every value kept, and the merged key's
	// spelling is the framework's to choose (RC3 keeps the later one here: max_age=0&MAX_AGE=999 reaches OpenIddict as MAX_AGE
	// alone, so max_age reads absent). The endpoint refuses any variant spelling, so the cookie is never judged without it.
	// Both orders are pinned by the theory below; these two are the downgrade orders observed on RC3.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_variant_spelled_max_age_never_drops_the_requirement()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var cookie = await host.SignInAsync(await AuthorizeHost.SeedUserAsync(fixture));
		host.Clock.Advance(TimeSpan.FromSeconds(120));
		var request = AuthorizeRequest.Create().Adding(Parameters.MaxAge, "0").Adding("MAX_AGE", "999");

		using var response = await host.AuthorizeAsync(request, cookie);

		Answer.Of(response, host).ShouldBeError(Errors.InvalidRequest, request[Parameters.State]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_variant_spelled_prompt_never_drops_login()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var cookie = await host.SignInAsync(await AuthorizeHost.SeedUserAsync(fixture));
		var request = AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.Login).Adding("PROMPT", "x");

		using var response = await host.AuthorizeAsync(request, cookie);

		Answer.Of(response, host).ShouldBeError(Errors.InvalidRequest, request[Parameters.State]);
	}

	/// <summary>
	///     Every parameter the endpoint reads, by its exact name, with an upper-case variant before it, after it, or in its
	///     place: which spelling the merged key keeps is the framework's to decide, so every order is pinned. Every row is a
	///     GET but one: a POST reads the form only, whose keys merge the same way, so one posted row pins that source too.
	/// </summary>
	public static TheoryData<string, string, bool> ReadParameterVariants
	{
		get
		{
			TheoryData<string, string, bool> data = [];
			foreach (var name in (string[])[
						Parameters.ClientId, Parameters.RedirectUri, Parameters.ResponseType, Parameters.Scope,
						Parameters.State, Parameters.Nonce, Parameters.CodeChallenge, Parameters.CodeChallengeMethod,
						Parameters.Prompt, Parameters.MaxAge, AuthorizeTransaction.MarkerParameter
					])
				foreach (var arrangement in (string[])["variant-first", "variant-second", "variant-only"])
					data.Add(name, arrangement, false);

			// max_age=0 then MAX_AGE=0: the order RC3's merge resolved to the later spelling, the I1 bypass, by form.
			data.Add(Parameters.MaxAge, "variant-second", true);
			return data;
		}
	}

	// I1, generalized: a case-variant spelling of any parameter the endpoint reads, beside or instead of the exact one, is
	// refused before a marker is minted or a code issued. Either OpenIddict refuses it (the exact name reads absent)
	// or the endpoint does; a fresh cookie is presented, so a slip would be issued a code.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(ReadParameterVariants))]
	protected async Task A_case_variant_spelling_of_a_read_parameter_is_refused(string parameter, string arrangement, bool post)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.SignInAsync(user);
		var created = AuthorizeRequest.Create();
		var exact = created.Pairs.Any(pair => pair.Key == parameter) ?
			created[parameter] :
			parameter switch
			{
				Parameters.Prompt => PromptValues.Login,
				Parameters.MaxAge => "0",
				_ => "x"
			};
		var variant = parameter.ToUpperInvariant();
		var request = arrangement switch
		{
			"variant-first" => created.Without(parameter).Adding(variant, exact).Adding(parameter, exact),
			"variant-second" => created.Without(parameter).Adding(parameter, exact).Adding(variant, exact),
			"variant-only" => created.Without(parameter).Adding(variant, exact),
			_ => throw new ArgumentOutOfRangeException(nameof(arrangement))
		};

		using var response = await host.AuthorizeAsync(request, cookie, post);

		var answer = Answer.Of(response, host);
		answer.Kind.ShouldBe(AnswerKind.Error, $"{response.StatusCode} {response.Headers.Location}");
		(answer.Error ?? await response.Content.ReadAsStringAsync(Cancellation)).ShouldContain(Errors.InvalidRequest);
		if (answer.Location is not null)
			host.PassedMarkers.Count.ShouldBe(1, "a redirected refusal is the endpoint's");
		(await host.ReadGrantsAsync(user.Id)).ShouldBeEmpty("no code was issued");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_repeated_state_is_refused_before_a_marker_is_minted()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);

		using var response = await host.AuthorizeAsync(AuthorizeRequest.Create().Adding(Parameters.State, "second"));

		var answer = Answer.Of(response, host);
		answer.Kind.ShouldBe(AnswerKind.Error);
		answer.Error.ShouldBe(Errors.InvalidRequest);
	}

	// One source: ASP.NET merges NORSE_REAUTH and norse_reauth into one key under one of the two spellings, and OpenIddict's
	// parameters (ordinal) keep that merge; a differently cased marker spelling is never honored, in either order.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[InlineData(true)]
	[InlineData(false)]
	protected async Task A_mixed_case_duplicate_marker_is_never_honored(bool variantFirst)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var (returnUrl, bound) = await BoundReentryAsync(host, await AuthorizeHost.SeedUserAsync(fixture));
		var marker = Query(returnUrl)["norse_reauth"].ToString();
		var path = returnUrl[..returnUrl.IndexOf('?', StringComparison.Ordinal)];
		List<KeyValuePair<string, StringValues>> parameters =
			[.. Query(returnUrl).Where(static pair => pair.Key != "norse_reauth")];
		KeyValuePair<string, StringValues> variant = new("NORSE_REAUTH", "x"), exact = new("norse_reauth", marker);
		List<KeyValuePair<string, StringValues>> markers = variantFirst ? [variant, exact] : [exact, variant];
		var mixed = path + QueryString.Create([.. parameters, .. markers]);
		var variantOnly = path + QueryString.Create([.. parameters, new("NORSE_REAUTH", marker)]);

		using var mixedResponse = await host.GetAsync(mixed, bound);
		using var variantResponse = await host.GetAsync(variantOnly, bound);

		Answer.Of(mixedResponse, host).Kind.ShouldNotBe(AnswerKind.Code);
		Answer.Of(variantResponse, host).Kind.ShouldNotBe(AnswerKind.Code);
		using var exactResponse = await host.GetAsync(returnUrl, bound);
		Answer.Of(exactResponse, host).Kind.ShouldBe(AnswerKind.Code, "the marker was never burned by the refused requests");
	}

	// §6.4: the login page does not redirect a signed-in user, so the challenge's login page re-proves the credential and
	// lands back on the re-entry, which is then issued a code. A later "already signed in" redirect breaks this fact.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Login_page_reproves_a_signed_in_user_and_lands_back()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture, configure: LoginPage.Compose, map: LoginPage.Map);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.SignInAsync(user);
		var request = AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.Login);
		using var challenge = await host.AuthorizeAsync(request, cookie);
		var answer = Answer.Of(challenge, host);
		var returnUrl = answer.ShouldBeChallenge();

		using var page = await host.GetAsync(new Uri(answer.Location!).PathAndQuery, cookie);
		page.StatusCode.ShouldBe(HttpStatusCode.OK, "the login page renders for a signed-in user");
		page.Headers.Location.ShouldBeNull();
		(await page.Content.ReadAsStringAsync(Cancellation)).ShouldContain("authn-login");

		KeyValuePair<string, string?>[] login = [new("user", user.Id.ToString()), new("returnUrl", returnUrl)];
		using var proved = await host.GetAsync(LoginPage.LoginPath + QueryString.Create(login), cookie);
		proved.StatusCode.ShouldBe(HttpStatusCode.OK);
		(await proved.Content.ReadAsStringAsync(Cancellation)).ShouldBe(returnUrl, "the handler lands back on the re-entry");
		var bound = AuthorizeHost.IdentityCookie(proved).ShouldNotBeNull("the re-proof re-issued the cookie");

		using var reentry = await host.GetAsync(returnUrl, bound);
		var issued = Answer.Of(reentry, host);
		issued.Kind.ShouldBe(AnswerKind.Code);
		issued.State.ShouldBe(request[Parameters.State]);
	}

	/// <summary>Asserts OpenIddict's own refusal: an error page, never a redirect. Answers the page.</summary>
	static async Task<string> ShouldBeRefusedAsync(HttpResponseMessage response, string error)
	{
		response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
		response.Headers.Location.ShouldBeNull("a request OpenIddict rejected is never redirected");
		var body = await response.Content.ReadAsStringAsync(Cancellation);
		body.ShouldContain(error);
		return body;
	}

	/// <summary>
	///     A bound re-entry: a fresh cookie's <c>prompt=login</c> challenge, then a sign-in landing on it. Answers the
	///     re-entry URL and the bound cookie.
	/// </summary>
	static async Task<(string ReturnUrl, string Cookie)> BoundReentryAsync(AuthorizeHost host, NorseUser user)
	{
		using var challenge = await host.AuthorizeAsync(AuthorizeRequest.Create().Adding(Parameters.Prompt, PromptValues.Login),
			await host.SignInAsync(user));
		var returnUrl = Answer.Of(challenge, host).ShouldBeChallenge();
		return (returnUrl, await host.SignInAsync(user, returnUrl));
	}

	/// <summary>
	///     Asserts the endpoint read no principal: <c>login_required</c> under <c>prompt=none</c>, else a challenge whose
	///     marker names no user.
	/// </summary>
	static void ShouldBeNoPrincipal(AuthorizeHost host, HttpResponseMessage response, AuthorizeRequest request, bool promptNone)
	{
		var answer = Answer.Of(response, host);
		if (promptNone)
		{
			answer.ShouldBeError(Errors.LoginRequired, request[Parameters.State]);
			return;
		}

		Marker(host, answer.ShouldBeChallenge()).UserId.ShouldBeNull("no principal was read, so the marker names no user");
	}

	/// <summary>Asserts a challenge carrying a new marker, not the one <paramref name="previous" /> carries.</summary>
	static void ShouldReChallenge(AuthorizeHost host, HttpResponseMessage response, string previous)
	{
		var returnUrl = Answer.Of(response, host).ShouldBeChallenge();
		Query(returnUrl)["norse_reauth"].ToString().ShouldNotBe(Query(previous)["norse_reauth"].ToString(),
			"the re-challenge mints a fresh marker");
	}

	static ReauthMarker Marker(AuthorizeHost host, string returnUrl)
	{
		host.Services.GetRequiredService<ReauthMarkers>()
			.TryUnprotect(Query(returnUrl)["norse_reauth"].ToString(), out var marker).ShouldBeTrue();
		return marker!;
	}

	static long Now(AuthorizeHost host) =>
		host.Clock.GetUtcNow().ToUnixTimeSeconds();

	static Dictionary<string, StringValues> Query(string url)
	{
		var query = url.IndexOf('?', StringComparison.Ordinal);
		return QueryHelpers.ParseQuery(query < 0 ? url : url[query..]);
	}

	/// <summary>The re-entry URL with <paramref name="name" /> set to <paramref name="value" />, everything else as it was.</summary>
	static string Replace(string url, string name, string value)
	{
		var path = url[..url.IndexOf('?', StringComparison.Ordinal)];
		var parameters = Query(url);
		parameters[name] = value;
		return path + QueryString.Create(parameters);
	}

	/// <summary>
	///     An identity cookie for <paramref name="user" /> carrying exactly the given <c>auth_time</c> values (none for
	///     <see langword="null" />) and, optionally, a <c>norse_reauth</c>, protected by the scheme's own ticket format: a
	///     cookie no Norse sign-in would write, for the endpoint's own reading of it.
	/// </summary>
	static async Task<string> CraftCookieAsync(AuthorizeHost host, NorseUser user, string[]? authTime, string? reauth = null)
	{
		await using var scope = host.Services.CreateAsyncScope();
		var services = scope.ServiceProvider;
		var claimsIdentity = services.GetRequiredService<IOptions<IdentityOptions>>().Value.ClaimsIdentity;
		var userManager = services.GetRequiredService<UserManager<NorseUser>>();
		var stamp = await userManager.GetSecurityStampAsync((await userManager.FindByIdAsync(user.Id.ToString())).ShouldNotBeNull());
		ClaimsIdentity identity = new(IdentityConstants.ApplicationScheme, claimsIdentity.UserNameClaimType,
			claimsIdentity.RoleClaimType);
		identity.AddClaim(new(claimsIdentity.UserIdClaimType, user.Id.ToString()));
		identity.AddClaim(new(claimsIdentity.SecurityStampClaimType, stamp!));
		foreach (var value in authTime ?? [])
			identity.AddClaim(new(NorseClaimTypes.AuthTime, value, ClaimValueTypes.Integer64));
		if (reauth is not null)
			identity.AddClaim(new(NorseSignInManager.ReauthClaimType, reauth));
		var options = services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>().Get(IdentityConstants.ApplicationScheme);
		AuthenticationProperties properties = new() { IssuedUtc = host.Clock.GetUtcNow() };
		return $"{options.Cookie.Name}={options.TicketDataFormat.Protect(new(new ClaimsPrincipal(identity), properties,
			IdentityConstants.ApplicationScheme))}";
	}

	static async Task<string> CraftCookieAsync(AuthorizeHost host, NorseUser user, long authTime, string reauth) =>
		await CraftCookieAsync(host, user, [authTime.ToString(CultureInfo.InvariantCulture)], reauth);

	/// <summary>What an authorize response is, to a browser.</summary>
	enum AnswerKind
	{
		/// <summary>Neither a redirect to the login page nor to the client.</summary>
		Other = 0,

		/// <summary>A redirect to the login page.</summary>
		Challenge = 1,

		/// <summary>A redirect to the client carrying a code.</summary>
		Code = 2,

		/// <summary>A protocol error: a redirect to the client carrying <c>error</c>, or an error page.</summary>
		Error = 3
	}

	/// <summary>One authorize response, read.</summary>
	/// <param name="Kind">What it is.</param>
	/// <param name="Location">The redirect, if any.</param>
	/// <param name="ReturnUrl">A challenge's <c>returnUrl</c>.</param>
	/// <param name="Code">The code.</param>
	/// <param name="State">The <c>state</c> the redirect to the client carries.</param>
	/// <param name="Error">The error.</param>
	sealed record Answer(AnswerKind Kind, string? Location, string? ReturnUrl, string? Code, string? State, string? Error)
	{
		public static Answer Of(HttpResponseMessage response, AuthorizeHost host)
		{
			if (response.StatusCode == HttpStatusCode.BadRequest)
				return new(AnswerKind.Error, null, null, null, null, null);
			if (response.StatusCode != HttpStatusCode.Redirect || response.Headers.Location is not { } location)
				return new(AnswerKind.Other, null, null, null, null, null);

			var url = location.OriginalString;
			var query = Query(url);
			if (url.StartsWith($"https://localhost{host.PathBase}/Account/Login?", StringComparison.Ordinal))
				return new(AnswerKind.Challenge, url, query["ReturnUrl"].ToString(), null, null, null);
			if (!url.StartsWith(AuthorizeHost.RedirectUri.AbsoluteUri, StringComparison.Ordinal)
				&& !url.StartsWith(AuthorizeHost.OtherRedirectUri.AbsoluteUri, StringComparison.Ordinal))
				return new(AnswerKind.Other, url, null, null, null, null);
			var state = query.TryGetValue(Parameters.State, out var value) ? value.ToString() : null;
			return query.TryGetValue(Parameters.Error, out var error) ?
				new(AnswerKind.Error, url, null, null, state, error.ToString()) :
				new(query.ContainsKey(Parameters.Code) ? AnswerKind.Code : AnswerKind.Other, url, null,
					query.TryGetValue(Parameters.Code, out var code) ? code.ToString() : null, state, null);
		}

		/// <summary>Asserts a challenge and answers its <c>returnUrl</c>.</summary>
		public string ShouldBeChallenge()
		{
			Kind.ShouldBe(AnswerKind.Challenge, Location);
			ReturnUrl.ShouldNotBeNullOrEmpty();
			return ReturnUrl;
		}

		/// <summary>Asserts a protocol error redirected to the client carrying <paramref name="state" />.</summary>
		public void ShouldBeError(string error, string state)
		{
			Kind.ShouldBe(AnswerKind.Error, Location);
			Location.ShouldNotBeNull("a validated client is redirected to");
			Error.ShouldBe(error);
			State.ShouldBe(state);
		}
	}
}
