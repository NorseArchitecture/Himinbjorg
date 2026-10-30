using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Norse.Identity.EntityFramework;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;
using TokenSet = Norse.Identity.Web.Server.Tests.OpenIddict.OpenIddictTestHost.TokenSet;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     Revocation and protocol errors (2026-10-29 OpenIddict spec §5.5, §5.7, §10.8, §10.9; plan Task 4.7), once per
///     provider, through the production endpoints over <see cref="AuthorizeHost" />: <c>/connect/revoke</c> is OpenIddict's
///     own endpoint (RFC 7009) under the Norse grant boundary, and every OpenIddict response answers OAuth's bare error,
///     never a description, a URI or an <c>Outcome</c> envelope.
/// </summary>
/// <remarks>
///     Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///     records: xUnit discovers them on each <see langword="sealed" /> provider class. Stamp rotation, lockout and
///     erasure (§10.8's first item) are <see cref="TokenEndpointSuite" />'s, and the revocation-first race is
///     <see cref="GrantBoundarySuite" />'s <c>Late_load(revocation)</c>.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class RevocationSuite(IdentityFixture fixture)
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	const string ConfidentialSecret = "revocation-secret-value";
	const string MissingToken = "missing token";
	const string MissingSecret = "missing secret";
	const string WrongSecret = "wrong secret";
	const string UnknownClient = "unknown client";

	/// <summary>How long a fact waits for a request to reach a pause point before failing instead of hanging.</summary>
	static readonly TimeSpan _pauseTimeout = TimeSpan.FromSeconds(30);

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <summary>A revocation request error, and the error it answers (§5.7).</summary>
	public static TheoryData<string, string> RequestErrors =>
		new()
		{
			{ MissingToken, Errors.InvalidRequest },
			{ MissingSecret, Errors.InvalidClient },
			{ WrongSecret, Errors.InvalidClient },
			{ UnknownClient, Errors.InvalidClient }
		};

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	// §10.8: a self-revoke of the current refresh token answers 200, revokes that token only and leaves the authorization
	// valid; the next refresh with it is reuse, so it answers invalid_grant and the grant ends. An independent grant of the
	// same user on the same client refreshes throughout.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Self_revoke_revokes_the_token_alone_and_its_next_refresh_ends_the_grant()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var grant = await SignInAsync(host);
		var independent = await SignInAsync(host, grant.User);
		var before = await host.ReadTokensAsync(grant.User.Id);
		var revokedId = await host.TokenIdAsync(grant.Tokens.RefreshToken);

		using (var revoked = await host.RevokeAsync(grant.Tokens.RefreshToken))
			await ShouldBeRevocationSuccessAsync(revoked);

		var after = await host.ReadTokensAsync(grant.User.Id);
		after[revokedId].Status.ShouldBe(Statuses.Revoked);
		after.Where(token => token.Key != revokedId).Select(static token => token.Value)
			.ShouldBe(before.Where(token => token.Key != revokedId).Select(static token => token.Value), ignoreOrder: true,
				"no other token changed");
		(await StatusAsync(host, grant)).ShouldBe(Statuses.Valid, "a self-revoke of a valid token ends no grant");
		var survivor = await RefreshAsync(host, independent.Tokens.RefreshToken);

		using (var refreshed = await host.RefreshAsync(grant.Tokens.RefreshToken))
			await ShouldBeErrorAsync(refreshed, HttpStatusCode.BadRequest, Errors.InvalidGrant);

		await ShouldBeEndedAsync(host, grant);
		survivor = await RefreshAsync(host, survivor.RefreshToken);
		await RefreshAsync(host, survivor.RefreshToken);
		(await StatusAsync(host, independent)).ShouldBe(Statuses.Valid);
	}

	// §10.8: rotate R0 into R1, then revoke R0. A redeemed token at revocation is reuse: 200, the authorization and both
	// tokens revoked, and R1 cannot refresh.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Revoking_a_predecessor_ends_the_grant()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var grant = await SignInAsync(host);
		var r1 = await RefreshAsync(host, grant.Tokens.RefreshToken);

		using (var revoked = await host.RevokeAsync(grant.Tokens.RefreshToken))
			await ShouldBeRevocationSuccessAsync(revoked);

		await ShouldBeEndedAsync(host, grant);
		var tokens = await host.ReadTokensAsync(grant.User.Id);
		tokens[await host.TokenIdAsync(grant.Tokens.RefreshToken)].Status.ShouldBe(Statuses.Revoked);
		tokens[await host.TokenIdAsync(r1.RefreshToken)].Status.ShouldBe(Statuses.Revoked);
		using var refreshed = await host.RefreshAsync(r1.RefreshToken);
		await ShouldBeErrorAsync(refreshed, HttpStatusCode.BadRequest, Errors.InvalidGrant);
	}

	// §10.8, refresh first: the refresh redeems and is held before its successor exists; the revocation then presents a
	// redeemed token, which is reuse and ends the grant. The refresh resumes and is issued a successor under the revoked
	// authorization, which cannot refresh. (Revocation first is GrantBoundarySuite's Late_load(revocation).)
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_refresh_that_redeems_first_loses_its_successor_to_the_revocation()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var grant = await SignInAsync(host);
		var afterRedemption = host.Pauses.Arm(PausePoint.AfterRedemption);
		var refresh = host.RefreshAsync(grant.Tokens.RefreshToken);
		await afterRedemption.Reached.WaitAsync(_pauseTimeout, Cancellation);

		using (var revoked = await host.RevokeAsync(grant.Tokens.RefreshToken))
			await ShouldBeRevocationSuccessAsync(revoked);
		(await StatusAsync(host, grant)).ShouldBe(Statuses.Revoked, "the revocation saw a redeemed token and ended the grant");
		afterRedemption.Release();
		using var won = await refresh;
		var successor = await OpenIddictTestHost.ReadTokensAsync(won, Cancellation);

		(await host.ReadTokensAsync(grant.User.Id))[await host.TokenIdAsync(successor.RefreshToken)].AuthorizationId
			.ShouldBe(grant.Authorization, "the successor is a row of the revoked authorization");
		using var refreshed = await host.RefreshAsync(successor.RefreshToken);
		await ShouldBeErrorAsync(refreshed, HttpStatusCode.BadRequest, Errors.InvalidGrant);
		(await StatusAsync(host, grant)).ShouldBe(Statuses.Revoked);
	}

	// §10.8 filters: an access token or an id token, at the revocation endpoint, the token endpoint or as the authorize
	// endpoint's id_token_hint, is never EndGrantOnReuse's. Every entry of the grant is first made non-valid, so a missing
	// filter would end it.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task End_grant_on_reuse_never_handles_access_tokens_or_id_token_hints()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var grant = await SignInAsync(host);
		await host.SetTokenStatusAsync(grant.Authorization, Statuses.Redeemed);

		// Whatever OpenIddict answers each, it is OpenIddict's answer: only the grant's survival is asserted.
		HttpResponseMessage[] answers =
		[
			await host.RevokeAsync(grant.Tokens.AccessToken),
			await host.RevokeAsync(grant.Tokens.IdentityToken),
			await host.RefreshAsync(grant.Tokens.AccessToken),
			await host.AuthorizeAsync(AuthorizeRequest.Create().Adding(Parameters.IdTokenHint, grant.Tokens.IdentityToken),
				grant.Cookie)
		];
		foreach (var answer in answers)
			answer.Dispose();

		(await StatusAsync(host, grant)).ShouldBe(Statuses.Valid, "no access token or id token ended the grant");
	}

	// §5.5, §10.8: authorization codes are not revocation targets. A valid code answers unsupported_token_type (400, the
	// error alone) and changes nothing: the code still redeems and its authorization stays valid.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_valid_code_at_revocation_is_unsupported_token_type_and_changes_nothing()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var request = AuthorizeRequest.Create();
		var code = await host.IssueCodeAsync(request, await host.SignInAsync(user));
		var before = await host.ReadTokensAsync(user.Id);

		using (var revoked = await host.RevokeAsync(code))
			await ShouldBeErrorAsync(revoked, HttpStatusCode.BadRequest, Errors.UnsupportedTokenType);

		(await host.ReadTokensAsync(user.Id)).Values.ShouldBe(before.Values, ignoreOrder: true, "nothing changed");
		using var redeemed = await host.RedeemAsync(code, request);
		await OpenIddictTestHost.ReadTokensAsync(redeemed, Cancellation);
		(await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem().Status.ShouldBe(Statuses.Valid);
	}

	// §5.5, §10.8: a redeemed code at revocation is reuse, seen during generic validation before ValidateTokenType: 200, the
	// authorization and every token revoked, and the grant's refresh token cannot refresh.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_redeemed_code_at_revocation_answers_200_and_ends_the_grant()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var grant = await SignInAsync(host);

		using (var revoked = await host.RevokeAsync(grant.Code))
			await ShouldBeRevocationSuccessAsync(revoked);

		await ShouldBeEndedAsync(host, grant);
		using var refreshed = await host.RefreshAsync(grant.Tokens.RefreshToken);
		await ShouldBeErrorAsync(refreshed, HttpStatusCode.BadRequest, Errors.InvalidGrant);
	}

	// §5.5, §10.8: OpenIddict accepts an access token at revocation and marks its entry revoked; it is not a grant token, so
	// the authorization stays valid and the refresh token still refreshes.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_access_token_at_revocation_answers_200_and_ends_no_grant()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var grant = await SignInAsync(host);

		using (var revoked = await host.RevokeAsync(grant.Tokens.AccessToken))
			await ShouldBeRevocationSuccessAsync(revoked);

		(await host.ReadTokensAsync(grant.User.Id)).Values
			.Single(static token => token.Type == TokenTypeIdentifiers.AccessToken).Status.ShouldBe(Statuses.Revoked);
		(await StatusAsync(host, grant)).ShouldBe(Statuses.Valid);
		await RefreshAsync(host, grant.Tokens.RefreshToken);
	}

	// §5.5's client contract: a refresh succeeded but its response was lost, so the client retries with the old token. The
	// retry is reuse: invalid_grant, the grant ends (the lost successor with it), and the client's next step, a new
	// authorization, is a new grant that works.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_retry_after_a_lost_refresh_response_ends_the_grant_and_a_new_authorization_follows()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var grant = await SignInAsync(host);
		var lost = await RefreshAsync(host, grant.Tokens.RefreshToken);

		using (var retry = await host.RefreshAsync(grant.Tokens.RefreshToken))
			await ShouldBeErrorAsync(retry, HttpStatusCode.BadRequest, Errors.InvalidGrant);

		await ShouldBeEndedAsync(host, grant);
		using (var successor = await host.RefreshAsync(lost.RefreshToken))
			await ShouldBeErrorAsync(successor, HttpStatusCode.BadRequest, Errors.InvalidGrant);
		var next = await SignInAsync(host, grant.User);
		next.Authorization.ShouldNotBe(grant.Authorization);
		await RefreshAsync(host, next.Tokens.RefreshToken);
	}

	// §5.7, §10.9: a revocation request error (a malformed request, failed client authentication) is OAuth's error alone.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(RequestErrors))]
	protected async Task Revocation_request_errors_carry_the_error_alone(string fault, string error)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var confidential = await RegisterConfidentialClientAsync(host);

		using var response = fault switch
		{
			MissingToken => await host.PostFormAsync(AuthorizeHost.RevocationPath, [new(Parameters.ClientId, AuthorizeHost.ClientId)]),
			MissingSecret => await host.RevokeAsync("irrelevant", confidential),
			WrongSecret => await host.RevokeAsync("irrelevant", confidential, "not-the-secret"),
			_ => await host.RevokeAsync("irrelevant", $"unknown-{Guid.NewGuid():N}")
		};

		response.IsSuccessStatusCode.ShouldBeFalse();
		(await MembersAsync(response)).ShouldBe([new(Parameters.Error, error)]);
	}

	// Client authentication at revocation follows the client's type (§5.7): the first-party public client is identified by
	// its id alone (the self-revoke facts above), and a confidential client must authenticate with its secret: with it the
	// revocation lands, and with a wrong one nothing is revoked.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_confidential_client_revokes_only_with_its_secret()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var confidential = await RegisterConfidentialClientAsync(host);
		using var minted = await host.PostTokenAsync([
			new(Parameters.GrantType, GrantTypes.ClientCredentials),
			new(Parameters.ClientId, confidential),
			new(Parameters.ClientSecret, ConfidentialSecret)
		]);
		var accessToken = (await MembersAsync(minted, HttpStatusCode.OK))
			.Single(static member => member.Key == Parameters.AccessToken).Value.ShouldNotBeNull();

		using (var refused = await host.RevokeAsync(accessToken, confidential, "not-the-secret"))
			await ShouldBeErrorAsync(refused, HttpStatusCode.Unauthorized, Errors.InvalidClient);
		(await MachineTokenStatusAsync(host, confidential)).ShouldBe(Statuses.Valid, "a refused client revokes nothing");
		using (var revoked = await host.RevokeAsync(accessToken, confidential, ConfidentialSecret))
			await ShouldBeRevocationSuccessAsync(revoked);

		(await MachineTokenStatusAsync(host, confidential)).ShouldBe(Statuses.Revoked);
	}

	// RFC 7009 §2.2, §5.7, §10.9: an unknown, expired, already-revoked or already-redeemed token answers exactly what a
	// successful revocation answers.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Unknown_expired_revoked_and_redeemed_tokens_answer_what_a_revocation_answers()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var revoked = await SignInAsync(host);
		var redeemed = await SignInAsync(host, revoked.User);
		await RefreshAsync(host, redeemed.Tokens.RefreshToken);
		var expired = await SignInAsync(host, revoked.User);
		using var success = await host.RevokeAsync(revoked.Tokens.RefreshToken);
		var expected = await AnswerAsync(success);
		expected.Status.ShouldBe(HttpStatusCode.OK);

		List<(string Case, Answer Answer)> answers = [];
		using (var response = await host.RevokeAsync($"unknown-{Guid.NewGuid():N}"))
			answers.Add(("unknown", await AnswerAsync(response)));
		using (var response = await host.RevokeAsync(revoked.Tokens.RefreshToken))
			answers.Add(("already revoked", await AnswerAsync(response)));
		using (var response = await host.RevokeAsync(redeemed.Tokens.RefreshToken))
			answers.Add(("already redeemed", await AnswerAsync(response)));
		host.Clock.Advance(TimeSpan.FromDays(15));
		using (var response = await host.RevokeAsync(expired.Tokens.RefreshToken))
			answers.Add(("expired", await AnswerAsync(response)));

		foreach (var (@case, answer) in answers)
			answer.ShouldBe(expected, @case);
	}

	// Every OpenIddict response, not only the three endpoints': the discovery document refuses a POST, and the error is the
	// bare one there too.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_discovery_error_carries_the_error_alone()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);

		using var response = await host.PostFormAsync("/.well-known/openid-configuration", []);

		await ShouldBeErrorAsync(response, HttpStatusCode.BadRequest, Errors.InvalidRequest);
	}

	// §5.7, §10.9: OpenIddict's endpoints answer OAuth, never Norse's Outcome/Problem envelope: the authorize endpoint's
	// redirected error and its error page, the token endpoint's error, and the revocation endpoint's error and success.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task No_endpoint_answers_an_outcome_envelope()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var grant = await SignInAsync(host);
		var request = AuthorizeRequest.Create().Adding(Parameters.MaxAge, "soon");

		using (var redirected = await host.AuthorizeAsync(request))
		{
			redirected.StatusCode.ShouldBe(HttpStatusCode.Redirect);
			var query = QueryHelpers.ParseQuery(new Uri(redirected.Headers.Location.ShouldNotBeNull().OriginalString).Query);
			query.Keys.ShouldBe([Parameters.Error, Parameters.State, Parameters.Iss], ignoreOrder: true);
			query[Parameters.Error].ToString().ShouldBe(Errors.InvalidRequest);
			await ShouldCarryNoEnvelopeAsync(redirected);
		}

		using (var page = await host.AuthorizeAsync(
			AuthorizeRequest.Create().With(Parameters.CodeChallengeMethod, CodeChallengeMethods.Plain)))
		{
			page.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
			page.Content.Headers.ContentType?.MediaType.ShouldBe("text/plain");
			(await page.Content.ReadAsStringAsync(Cancellation)).Split('\n', StringSplitOptions.RemoveEmptyEntries)
				.Select(static line => line.Split(':', 2)[0].Trim()).ShouldBe([Parameters.Error]);
			await ShouldCarryNoEnvelopeAsync(page);
		}

		using (var token = await host.RedeemAsync("not-a-code", AuthorizeRequest.Create()))
			await ShouldBeErrorAsync(token, HttpStatusCode.BadRequest, Errors.InvalidGrant);
		using (var revokeError = await host.PostFormAsync(AuthorizeHost.RevocationPath,
			[new(Parameters.ClientId, AuthorizeHost.ClientId)]))
			await ShouldBeErrorAsync(revokeError, HttpStatusCode.BadRequest, Errors.InvalidRequest);
		using (var revoked = await host.RevokeAsync(grant.Tokens.RefreshToken))
			await ShouldBeRevocationSuccessAsync(revoked);
	}

	/// <summary>A signed-in user's whole code flow, through the production endpoints.</summary>
	async Task<Grant> SignInAsync(AuthorizeHost host, NorseUser? user = null)
	{
		user ??= await AuthorizeHost.SeedUserAsync(fixture);
		var request = AuthorizeRequest.Create();
		var cookie = await host.SignInAsync(user);
		var code = await host.IssueCodeAsync(request, cookie);
		using var response = await host.RedeemAsync(code, request);
		var tokens = await OpenIddictTestHost.ReadTokensAsync(response, Cancellation);
		var authorization = (await host.ReadTokensAsync(user.Id))[await host.TokenIdAsync(tokens.RefreshToken)].AuthorizationId
			.ShouldNotBeNull();
		return new(user, cookie, code, tokens, authorization);
	}

	static async Task<TokenSet> RefreshAsync(AuthorizeHost host, string refreshToken)
	{
		using var response = await host.RefreshAsync(refreshToken);
		return await OpenIddictTestHost.ReadTokensAsync(response, Cancellation);
	}

	static async Task<string?> StatusAsync(AuthorizeHost host, Grant grant) =>
		(await host.ReadGrantsAsync(grant.User.Id)).Single(row => row.Id == grant.Authorization).Status;

	/// <summary>The grant ended: its authorization and every one of its tokens read <c>revoked</c>.</summary>
	static async Task ShouldBeEndedAsync(AuthorizeHost host, Grant grant)
	{
		var row = (await host.ReadGrantsAsync(grant.User.Id)).Single(row => row.Id == grant.Authorization);
		row.Status.ShouldBe(Statuses.Revoked);
		row.TokenStatuses.ShouldNotBeEmpty();
		row.TokenStatuses.ShouldAllBe(static status => status == Statuses.Revoked);
	}

	/// <summary>A confidential client allowed the client-credentials grant and revocation; answers its client id.</summary>
	static async Task<string> RegisterConfidentialClientAsync(AuthorizeHost host)
	{
		var clientId = $"revocation-confidential-{Guid.NewGuid():N}";
		await using var scope = host.Services.CreateAsyncScope();
		await scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>().CreateAsync(new OpenIddictApplicationDescriptor
		{
			ClientId = clientId,
			ClientSecret = ConfidentialSecret,
			ClientType = ClientTypes.Confidential,
			Permissions =
			{
				Permissions.Endpoints.Token,
				Permissions.Endpoints.Revocation,
				Permissions.GrantTypes.ClientCredentials
			}
		}, Cancellation);
		return clientId;
	}

	/// <summary>The status of the one access token minted for <paramref name="clientId" />'s client-credentials grant.</summary>
	static async Task<string?> MachineTokenStatusAsync(AuthorizeHost host, string clientId)
	{
		await using var scope = host.Services.CreateAsyncScope();
		var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
		List<string?> statuses = [];
		await foreach (var token in manager.FindBySubjectAsync(clientId, Cancellation))
			statuses.Add(await manager.GetStatusAsync(token, Cancellation));
		return statuses.ShouldHaveSingleItem();
	}

	/// <summary>A successful revocation: HTTP 200 and an empty JSON object, no envelope.</summary>
	static async Task ShouldBeRevocationSuccessAsync(HttpResponseMessage response) =>
		(await MembersAsync(response, HttpStatusCode.OK)).ShouldBeEmpty();

	/// <summary>An OAuth error: the status, and a JSON body whose only member is <c>error</c>.</summary>
	static async Task ShouldBeErrorAsync(HttpResponseMessage response, HttpStatusCode status, string error) =>
		(await MembersAsync(response, status)).ShouldBe([new(Parameters.Error, error)]);

	/// <summary>The members of a JSON body, after asserting the status (when given) and that no envelope came back.</summary>
	static async Task<KeyValuePair<string, string?>[]> MembersAsync(HttpResponseMessage response, HttpStatusCode? status = null)
	{
		var body = await response.Content.ReadAsStringAsync(Cancellation);
		if (status is { } expected)
			response.StatusCode.ShouldBe(expected, body);
		await ShouldCarryNoEnvelopeAsync(response);
		response.Content.Headers.ContentType?.MediaType.ShouldBe("application/json");
		using var document = JsonDocument.Parse(body);
		return [.. document.RootElement.EnumerateObject().Select(static member => new KeyValuePair<string, string?>(member.Name,
			member.Value.ValueKind is JsonValueKind.String ? member.Value.GetString() : member.Value.GetRawText()))];
	}

	/// <summary>
	///     Neither a problem document nor anything of <c>Outcome</c>'s <c>Problem</c>: no category, errors map, correlation
	///     id, receipt, code or next hop, and no description or URI.
	/// </summary>
	static async Task ShouldCarryNoEnvelopeAsync(HttpResponseMessage response)
	{
		response.Content.Headers.ContentType?.MediaType.ShouldNotBe("application/problem+json");
		var body = await response.Content.ReadAsStringAsync(Cancellation);
		foreach (var member in (string[])["category", "errors", "correlationId", "receipt", "nextUrl", "title", "detail",
			Parameters.ErrorDescription, Parameters.ErrorUri])
			body.ShouldNotContain($"\"{member}\"", Case.Insensitive);
		body.ShouldNotContain(Parameters.ErrorDescription);
		body.ShouldNotContain(Parameters.ErrorUri);
	}

	static async Task<Answer> AnswerAsync(HttpResponseMessage response) =>
		new(response.StatusCode, response.Content.Headers.ContentType?.ToString(),
			await response.Content.ReadAsStringAsync(Cancellation));

	/// <summary>A response, as a client can tell one from another.</summary>
	sealed record Answer(HttpStatusCode Status, string? ContentType, string Body);

	/// <summary>A completed code flow: the user, the cookie that authorized it, its code, the tokens, and its authorization.</summary>
	sealed record Grant(NorseUser User, string Cookie, string Code, TokenSet Tokens, Guid Authorization);
}
