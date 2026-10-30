using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Norse.Abstractions.Components.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.OpenIddict;
using Norse.Primitives;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using TokenSet = Norse.Identity.Web.Server.Tests.OpenIddict.OpenIddictTestHost.TokenSet;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     The production token endpoint for the code and refresh grants (2026-10-29 OpenIddict spec §5.3, §5.4, §5.7, §10.5;
///     plan Task 4.5), once per provider, over <see cref="AuthorizeHost" />: the grant carries its authentication (<c>sub</c>,
///     <c>auth_time</c>, <c>norse_stamp</c>), redemption re-checks the live user, and a refused grant ends.
/// </summary>
/// <remarks>
///     Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///     records: xUnit discovers them on each <see langword="sealed" /> provider class.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class TokenEndpointSuite(IdentityFixture fixture)
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	const string Code = "code";
	const string Refresh = "refresh";

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <summary>The two grants the endpoint redeems.</summary>
	public static TheoryData<string> Grants => [Code, Refresh];

	/// <summary>The three claims a grant must carry, each missing from each grant.</summary>
	public static TheoryData<string, string> GrantClaims =>
		new()
		{
			{ Claims.Subject, Code }, { NorseClaimTypes.AuthTime, Code }, { UserPrincipalFactory.StampClaimType, Code },
			{ Claims.Subject, Refresh }, { NorseClaimTypes.AuthTime, Refresh }, { UserPrincipalFactory.StampClaimType, Refresh }
		};

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	// §10.3's happy path, through the production exchange: the code's stamp is the cookie's (T4-8), the access token is the
	// user's audience with the cookie's auth_time and no role, the id token is the client's, and a refresh token is issued.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Code_flow_happy_path()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.SignInAsync(user);
		var signedIn = host.ReadCookie(cookie);
		var request = AuthorizeRequest.Create();
		var code = await host.IssueCodeAsync(request, cookie);

		(await host.UnprotectAsync(code)).FindAll(UserPrincipalFactory.StampClaimType).ShouldHaveSingleItem().Value
			.ShouldBe(signedIn.FindAll(StampClaimType(host)).ShouldHaveSingleItem().Value, "the code carries the cookie's stamp");

		using var response = await host.RedeemAsync(code, request);

		var tokens = await OpenIddictTestHost.ReadTokensAsync(response, Cancellation);
		JsonWebToken
			access = new(tokens.AccessToken),
			identity = new(tokens.IdentityToken);
		access.Audiences.ShouldBe([NorseAudiences.User]);
		access.Subject.ShouldBe(user.Id.ToString());
		access.GetClaim(NorseClaimTypes.AuthTime).Value.ShouldBe(AuthTime(signedIn));
		access.Claims.ShouldNotContain(static claim => IsRole(claim.Type));
		identity.Audiences.ShouldBe([AuthorizeHost.ClientId]);
		identity.Subject.ShouldBe(user.Id.ToString());
		identity.GetClaim(NorseClaimTypes.AuthTime).Value.ShouldBe(AuthTime(signedIn));
		tokens.RefreshToken.ShouldNotBeNullOrEmpty();
		var grant = (await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem();
		grant.Status.ShouldBe(Statuses.Valid);
		grant.TokenTypes.ShouldBe([
			TokenTypeIdentifiers.Private.AuthorizationCode, TokenTypeIdentifiers.AccessToken,
			TokenTypeIdentifiers.IdentityToken, TokenTypeIdentifiers.RefreshToken
		], ignoreOrder: true, "every token of the exchange is attached to the code's one authorization");
	}

	// §5.4 step 2 (ruling 11): a stamp rotation between issuance and redemption refuses the grant and ends it, on a code and
	// on a refresh token alike.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(Grants))]
	protected async Task Stamp_rotation_between_issuance_and_redemption_fails_with_invalid_grant(string grant)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var issued = await IssueAsync(host, user, grant);
		await RotateStampAsync(user);

		using var response = await issued.PresentAsync(host);

		await ShouldBeInvalidGrantAsync(response);
		var row = (await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem();
		row.Status.ShouldBe(Statuses.Revoked, "the refused grant ended");
		row.TokenStatuses.ShouldNotBeEmpty();
		row.TokenStatuses.ShouldAllBe(static status => status == Statuses.Revoked);
	}

	// Buvy's lockout ruling (final): a failed-password lockout blocks credential sign-in only. It neither refuses nor ends an
	// already-issued grant: a pending code still redeems, an existing refresh grant still refreshes, and an independent grant
	// of the same user is untouched. The user is locked by real wrong passwords through the login handler.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(Grants))]
	protected async Task A_failed_password_lockout_blocks_only_credential_sign_in(string grant)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var issued = await IssueAsync(host, user, grant);
		var independent = await IssueAsync(host, user, Refresh);
		await host.LockOutByFailedPasswordsAsync(user);

		(await host.LoginAsync(user, AuthorizeHost.Password)).TryGetValue(out Failed _)
			.ShouldBeTrue("the right password is still refused during the lockout");
		using var presented = await issued.PresentAsync(host);
		using var other = await independent.PresentAsync(host);

		presented.StatusCode.ShouldBe(HttpStatusCode.OK, "the issued grant is still usable");
		(await OpenIddictTestHost.ReadTokensAsync(presented, Cancellation)).RefreshToken.ShouldNotBeNullOrEmpty();
		other.StatusCode.ShouldBe(HttpStatusCode.OK, "the independent grant is unaffected");
		var rows = await host.ReadGrantsAsync(user.Id);
		rows.Count.ShouldBe(2);
		rows.ShouldAllBe(static row => row.Status == Statuses.Valid, "a lockout ends no grant");
	}

	// The same ruling: administrative withdrawal is an explicit stamp change or a grant revocation, never inferred from a
	// lockout date, so even a far-future lockout end leaves an issued grant usable.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(Grants))]
	protected async Task A_lockout_date_alone_never_refuses_an_issued_grant(string grant)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var issued = await IssueAsync(host, user, grant);
		var userManager = fixture.CreateUserManager();
		(await userManager.SetLockoutEndDateAsync((await userManager.FindByIdAsync(user.Id.ToString())).ShouldNotBeNull(),
			DateTimeOffset.UtcNow.AddYears(100))).Succeeded.ShouldBeTrue();

		using var response = await issued.PresentAsync(host);

		response.StatusCode.ShouldBe(HttpStatusCode.OK);
		(await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem().Status.ShouldBe(Statuses.Valid);
	}

	// The same ruling: a stamp rotation during a lockout still refuses the redemption and ends the presented grant, and only
	// that one: the exchange ends the grant it was handed, not every grant of the user.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(Grants))]
	protected async Task Stamp_rotation_during_a_lockout_still_ends_the_presented_grant(string grant)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var issued = await IssueAsync(host, user, grant);
		await IssueAsync(host, user, Refresh);
		var presentedGrant = await AuthorizationOfAsync(host, user, issued.Code);
		await host.LockOutByFailedPasswordsAsync(user);
		await RotateStampAsync(user);

		using var response = await issued.PresentAsync(host);

		await ShouldBeInvalidGrantAsync(response);
		var rows = await host.ReadGrantsAsync(user.Id);
		rows.Count.ShouldBe(2);
		var ended = rows.Single(row => row.Id == presentedGrant);
		ended.Status.ShouldBe(Statuses.Revoked, "the presented grant ended");
		ended.TokenStatuses.ShouldAllBe(static status => status == Statuses.Revoked);
		var untouched = rows.Single(row => row.Id != presentedGrant);
		untouched.Status.ShouldBe(Statuses.Valid, "the exchange ends only the grant it was handed");
		untouched.TokenStatuses.ShouldContain(Statuses.Valid);
	}

	// The same ruling: reuse during a lockout still ends the grant. The first presentation is usable; presenting the same
	// code or refresh token again is reuse.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(Grants))]
	protected async Task Reuse_during_a_lockout_still_ends_the_grant(string grant)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var issued = await IssueAsync(host, user, grant);
		await host.LockOutByFailedPasswordsAsync(user);
		using (var first = await issued.PresentAsync(host))
			first.StatusCode.ShouldBe(HttpStatusCode.OK, "the first presentation is usable during the lockout");

		using var reused = await issued.PresentAsync(host);

		await ShouldBeInvalidGrantAsync(reused);
		var row = (await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem();
		row.Status.ShouldBe(Statuses.Revoked, "reuse ended the grant");
		row.TokenStatuses.ShouldAllBe(static status => status == Statuses.Revoked);
	}

	// §5.5 (erasure): ErasureService deletes the subject's authorizations and tokens, so they are absent, not revoked, and the
	// grant can no longer be redeemed.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(Grants))]
	protected async Task Erasure_between_issuance_and_redemption_fails_with_invalid_grant(string grant)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var issued = await IssueAsync(host, user, grant);
		(await host.CountTokensAsync(user.Id)).ShouldBePositive();

		await using (var scope = host.Services.CreateAsyncScope())
			(await scope.ServiceProvider.GetRequiredService<ErasureService>().ShredAsync(user.Id, Cancellation))
				.TryGetValue(out Success<ErasureReceipt> _).ShouldBeTrue();
		using var response = await issued.PresentAsync(host);

		await ShouldBeInvalidGrantAsync(response);
		(await host.ReadGrantsAsync(user.Id)).ShouldBeEmpty("erasure deleted the authorization");
		(await host.CountTokensAsync(user.Id)).ShouldBe(0, "erasure deleted every token");
	}

	// §5.4 step 3: a refresh mints from the grant, so auth_time never advances, however late the refresh.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Auth_time_is_carried_unchanged_across_refreshes()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.SignInAsync(user);
		var authTime = AuthTime(host.ReadCookie(cookie));
		var request = AuthorizeRequest.Create();
		using var redeemed = await host.RedeemAsync(await host.IssueCodeAsync(request, cookie), request);
		var tokens = await OpenIddictTestHost.ReadTokensAsync(redeemed, Cancellation);

		for (var refresh = 1; refresh <= 5; refresh++)
		{
			host.Clock.Advance(TimeSpan.FromDays(1));
			using var response = await host.RefreshAsync(tokens.RefreshToken);
			tokens = await OpenIddictTestHost.ReadTokensAsync(response, Cancellation);

			new JsonWebToken(tokens.AccessToken).GetClaim(NorseClaimTypes.AuthTime).Value.ShouldBe(authTime, $"refresh {refresh}");
			new JsonWebToken(tokens.IdentityToken).GetClaim(NorseClaimTypes.AuthTime).Value.ShouldBe(authTime, $"refresh {refresh}");
			(await host.UnprotectAsync(tokens.RefreshToken)).FindAll(NorseClaimTypes.AuthTime).ShouldHaveSingleItem().Value
				.ShouldBe(authTime, $"refresh {refresh}");
		}

		authTime.ShouldBe(AuthTime(host.ReadCookie(cookie)), "the cookie itself was never re-stamped");
	}

	// §5.3: the stamp rides the server-only grants and never a public token, through a refresh too.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Norse_stamp_is_in_code_and_refresh_only()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.SignInAsync(user);
		var stamp = host.ReadCookie(cookie).FindAll(StampClaimType(host)).ShouldHaveSingleItem().Value;
		var request = AuthorizeRequest.Create();
		var code = await host.IssueCodeAsync(request, cookie);
		using var redeemed = await host.RedeemAsync(code, request);
		var first = await OpenIddictTestHost.ReadTokensAsync(redeemed, Cancellation);
		using var refreshed = await host.RefreshAsync(first.RefreshToken);
		var second = await OpenIddictTestHost.ReadTokensAsync(refreshed, Cancellation);

		foreach (var grant in (string[])[code, first.RefreshToken, second.RefreshToken])
			(await host.UnprotectAsync(grant)).FindAll(UserPrincipalFactory.StampClaimType).ShouldHaveSingleItem().Value
				.ShouldBe(stamp);
		foreach (var token in (TokenSet[])[first, second])
		{
			new JsonWebToken(token.AccessToken).Claims.ShouldNotContain(static claim =>
				claim.Type == UserPrincipalFactory.StampClaimType);
			new JsonWebToken(token.IdentityToken).Claims.ShouldNotContain(static claim =>
				claim.Type == UserPrincipalFactory.StampClaimType);
		}
	}

	// §5.3: a user with a role signs in with a role-bearing cookie, and none of the four tokens carries a role.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task User_tokens_carry_no_role_claims()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var role = $"token-{Guid.NewGuid():N}";
		(await fixture.CreateRoleManager().CreateAsync(new NorseRole { Name = role })).Succeeded.ShouldBeTrue();
		var withRole = fixture.CreateUserManager();
		(await withRole.AddToRoleAsync((await withRole.FindByIdAsync(user.Id.ToString())).ShouldNotBeNull(), role))
			.Succeeded.ShouldBeTrue();
		var cookie = await host.SignInAsync(user);
		host.ReadCookie(cookie).Claims.ShouldContain(claim => IsRole(claim.Type) && claim.Value == role,
			"the cookie carries the role, so its absence below means something");
		var request = AuthorizeRequest.Create();
		var code = await host.IssueCodeAsync(request, cookie);
		using var response = await host.RedeemAsync(code, request);
		var tokens = await OpenIddictTestHost.ReadTokensAsync(response, Cancellation);

		new JsonWebToken(tokens.AccessToken).Claims.ShouldNotContain(static claim => IsRole(claim.Type));
		new JsonWebToken(tokens.IdentityToken).Claims.ShouldNotContain(static claim => IsRole(claim.Type));
		(await host.UnprotectAsync(code)).Claims.ShouldNotContain(static claim => IsRole(claim.Type));
		(await host.UnprotectAsync(tokens.RefreshToken)).Claims.ShouldNotContain(static claim => IsRole(claim.Type));
	}

	// §5.4 step 1: a grant without exactly the three facts it must carry is refused, a code and a refresh token alike. The
	// grant is issued by the production endpoints and loses the claim only on its way into the code (or the refresh token the
	// code's redemption issues), after OpenIddict prepared that token's principal.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(GrantClaims))]
	protected async Task A_grant_missing_sub_auth_time_or_stamp_is_invalid_grant(string claim, string grant)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture, configure: builder => builder.Services
			.AddOpenIddict()
			.AddServer(server => server
				.AddEventHandler<ProcessSignInContext>(handler => handler
					.UseInlineHandler(context => Strip(grant == Code ? context.AuthorizationCodePrincipal : null))
					.SetOrder(PrepareAuthorizationCodePrincipal.Descriptor.Order + 1))
				.AddEventHandler<ProcessSignInContext>(handler => handler
					.UseInlineHandler(context => Strip(grant == Refresh ? context.RefreshTokenPrincipal : null))
					.SetOrder(PrepareRefreshTokenPrincipal.Descriptor.Order + 1))));
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var issued = await IssueAsync(host, user, grant);
		(await host.UnprotectAsync(issued.RefreshToken ?? issued.Code)).FindAll(claim).ShouldBeEmpty("the grant lost the claim");

		using var response = await issued.PresentAsync(host);

		await ShouldBeInvalidGrantAsync(response);

		ValueTask Strip(ClaimsPrincipal? principal)
		{
			if (principal?.Identity is ClaimsIdentity identity)
				foreach (var found in identity.FindAll(claim).ToList())
					identity.RemoveClaim(found);
			return ValueTask.CompletedTask;
		}
	}

	// §5.7: a token-endpoint error is the JSON body with the required error member and nothing optional, here OpenIddict's own
	// refusal of a code it never issued.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Token_errors_carry_no_description_and_no_uri()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);

		using var response = await host.RedeemAsync("not-a-code", AuthorizeRequest.Create());

		await ShouldBeInvalidGrantAsync(response);
	}

	// §5.7: invalid_client where applicable, the same shape.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_unknown_client_is_invalid_client_with_no_description()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);

		using var response = await host.RefreshAsync("irrelevant", $"unknown-{Guid.NewGuid():N}");

		response.IsSuccessStatusCode.ShouldBeFalse();
		(await ErrorMembersAsync(response)).ShouldBe([new(Parameters.Error, Errors.InvalidClient)]);
	}

	/// <summary>A code, or a refresh token from that code's redemption, ready to be presented.</summary>
	static async Task<Issued> IssueAsync(AuthorizeHost host, NorseUser user, string grant)
	{
		var request = AuthorizeRequest.Create();
		var code = await host.IssueCodeAsync(request, await host.SignInAsync(user));
		if (grant == Code)
			return new(request, code, null);

		using var response = await host.RedeemAsync(code, request);
		return new(request, code, (await OpenIddictTestHost.ReadTokensAsync(response, Cancellation)).RefreshToken);
	}

	/// <summary>Rotates <paramref name="user" />'s security stamp through the real managers.</summary>
	async Task RotateStampAsync(NorseUser user)
	{
		var userManager = fixture.CreateUserManager();
		(await userManager.UpdateSecurityStampAsync((await userManager.FindByIdAsync(user.Id.ToString())).ShouldNotBeNull()))
			.Succeeded.ShouldBeTrue();
	}

	/// <summary>The authorization <paramref name="code" />'s row links.</summary>
	static async Task<Guid> AuthorizationOfAsync(AuthorizeHost host, NorseUser user, string code) =>
		(await host.ReadTokensAsync(user.Id))[await host.TokenIdAsync(code)].AuthorizationId.ShouldNotBeNull();

	/// <summary>Asserts HTTP 400 and the body <c>{"error":"invalid_grant"}</c>: no description, no URI, no envelope.</summary>
	static async Task ShouldBeInvalidGrantAsync(HttpResponseMessage response)
	{
		response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
		(await ErrorMembersAsync(response)).ShouldBe([new(Parameters.Error, Errors.InvalidGrant)]);
	}

	static async Task<KeyValuePair<string, string?>[]> ErrorMembersAsync(HttpResponseMessage response)
	{
		response.Content.Headers.ContentType?.MediaType.ShouldBe("application/json");
		using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
		return [.. body.RootElement.EnumerateObject().Select(static member => new KeyValuePair<string, string?>(member.Name,
			member.Value.ValueKind is JsonValueKind.String ? member.Value.GetString() : member.Value.GetRawText()))];
	}

	static string AuthTime(ClaimsPrincipal principal) =>
		principal.FindAll(NorseClaimTypes.AuthTime).ShouldHaveSingleItem().Value;

	static string StampClaimType(AuthorizeHost host) =>
		host.Services.GetRequiredService<IOptions<IdentityOptions>>().Value.ClaimsIdentity.SecurityStampClaimType;

	static bool IsRole(string type) =>
		type is Claims.Role or ClaimTypes.Role;

	/// <summary>A grant ready to present: the code, and the refresh token when the fact presents that instead.</summary>
	sealed record Issued(AuthorizeRequest Request, string Code, string? RefreshToken)
	{
		public Task<HttpResponseMessage> PresentAsync(AuthorizeHost host) =>
			RefreshToken is null ?
				host.RedeemAsync(Code, Request) :
				host.RefreshAsync(RefreshToken);
	}
}
