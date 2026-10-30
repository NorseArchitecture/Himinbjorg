using System.Collections.Concurrent;
using System.Data.Common;
using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.OpenIddict;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using TokenSet = Norse.Identity.Web.Server.Tests.OpenIddict.OpenIddictTestHost.TokenSet;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     The guarded redemption and the grant boundary (2026-10-29 OpenIddict spec §5.5, §10.6, §10.7; plan Task 4.6), once
///     per provider, through the production authorize and token endpoints (Train 4 ruling PF2) over
///     <see cref="AuthorizeHost" />: every interleaving is driven by the named <see cref="PausePoints" />, never by
///     releasing two requests at one barrier, and the production <see cref="GrantTermination" /> runs behind a journal that
///     records the authorization each grant end was resolved to.
/// </summary>
/// <remarks>
///     Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///     records: xUnit discovers them on each <see langword="sealed" /> provider class.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class GrantBoundarySuite(IdentityFixture fixture)
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	const string TokenId = "token id";
	const string AuthorizationId = "authorization id";
	const string Refresh = "refresh";
	const string Revocation = "revocation";

	/// <summary>How long a fact waits for a request to reach a pause point before failing instead of hanging.</summary>
	static readonly TimeSpan _pauseTimeout = TimeSpan.FromSeconds(30);

	readonly ConcurrentQueue<Guid> _ended = new();
	volatile bool _strip;

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <summary>Which id a fail-closed fact strips, and where the token is then presented.</summary>
	public static TheoryData<string, string> StrippedAtValidation =>
		new() { { TokenId, Refresh }, { AuthorizationId, Refresh }, { TokenId, Revocation }, { AuthorizationId, Revocation } };

	/// <summary>Which id a fail-closed fact strips from the grant on its way into redemption.</summary>
	public static TheoryData<string> StrippedAtRedemption => [TokenId, AuthorizationId];

	/// <summary>What lands between a paused request's validation and its redemption.</summary>
	public static TheoryData<string> LateLoads => [Refresh, Revocation];

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	/// <summary>Every authorization a grant end was asked for, in order: the id the boundary resolved.</summary>
	IReadOnlyList<Guid> Ended => [.. _ended];

	// §10.6: a refresh rotates the token: a new one is issued, the presented one is redeemed, and the grant stays valid.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Rotation_issues_a_new_refresh_token()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await StartAsync();
		var grant = await SignInAsync(host);

		var rotated = await RefreshAsync(host, grant.Tokens.RefreshToken);

		rotated.RefreshToken.ShouldNotBe(grant.Tokens.RefreshToken);
		var tokens = await host.ReadTokensAsync(grant.User.Id);
		tokens[await host.TokenIdAsync(grant.Tokens.RefreshToken)].Status.ShouldBe(Statuses.Redeemed);
		tokens[await host.TokenIdAsync(rotated.RefreshToken)].Status.ShouldBe(Statuses.Valid);
		(await host.ReadGrantsAsync(grant.User.Id)).ShouldHaveSingleItem().Status.ShouldBe(Statuses.Valid);
		Ended.ShouldBeEmpty();
	}

	// §4.5 fact 3 (Task 0.3's continuity) again, through the production endpoints: code → R0 → R1 → R2 keeps one
	// authorization, asserted on the rows, and no refresh creates another.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Production_refresh_chain_keeps_one_authorization()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await StartAsync();
		var grant = await SignInAsync(host);
		var r1 = await RefreshAsync(host, grant.Tokens.RefreshToken);
		await RefreshAsync(host, r1.RefreshToken);

		var row = (await host.ReadGrantsAsync(grant.User.Id)).ShouldHaveSingleItem();
		row.Id.ShouldBe(grant.Authorization);
		row.Status.ShouldBe(Statuses.Valid);
		var tokens = (await host.ReadTokensAsync(grant.User.Id)).Values.ToList();
		tokens.ShouldAllBe(token => token.AuthorizationId == grant.Authorization);
		tokens.Count(static token => token.Type == TokenTypeIdentifiers.RefreshToken).ShouldBe(3);
		tokens.Count(static token => token.Type == TokenTypeIdentifiers.Private.AuthorizationCode).ShouldBe(1);
	}

	// §10.6: the redeemed refresh token presented again, sequentially, is reuse caught at validation: invalid_grant, the
	// authorization and every one of its tokens revoked, and the rotated successor dead with them.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Sequential_replay_ends_the_grant()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await StartAsync();
		var grant = await SignInAsync(host);
		var rotated = await RefreshAsync(host, grant.Tokens.RefreshToken);

		using (var replay = await host.RefreshAsync(grant.Tokens.RefreshToken))
			await ShouldBeInvalidGrantAsync(replay);

		Ended.ShouldBe([grant.Authorization]);
		await ShouldBeEndedAsync(host, grant);
		using var successor = await host.RefreshAsync(rotated.RefreshToken);
		await ShouldBeInvalidGrantAsync(successor);
	}

	// §10.6: the redeemed code presented again does the same.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Redeemed_code_replay_ends_the_grant()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await StartAsync();
		var grant = await SignInAsync(host);

		using (var replay = await host.RedeemAsync(grant.Code, grant.Request))
			await ShouldBeInvalidGrantAsync(replay);

		Ended.ShouldBe([grant.Authorization]);
		await ShouldBeEndedAsync(host, grant);
		using var refresh = await host.RefreshAsync(grant.Tokens.RefreshToken);
		await ShouldBeInvalidGrantAsync(refresh);
	}

	// §10.6: a second sign-in by the same user on the same client is an independent grant, and refreshes throughout the
	// first grant's end.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_independent_grant_survives()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await StartAsync();
		var ending = await SignInAsync(host);
		var independent = await SignInAsync(host, ending.User);
		independent.Authorization.ShouldNotBe(ending.Authorization);
		var survivor = await RefreshAsync(host, independent.Tokens.RefreshToken);
		await RefreshAsync(host, ending.Tokens.RefreshToken);

		using (var replay = await host.RefreshAsync(ending.Tokens.RefreshToken))
			await ShouldBeInvalidGrantAsync(replay);
		survivor = await RefreshAsync(host, survivor.RefreshToken);
		await RefreshAsync(host, survivor.RefreshToken);

		Ended.ShouldBe([ending.Authorization]);
		var grants = await host.ReadGrantsAsync(ending.User.Id);
		grants.Count.ShouldBe(2);
		grants.Single(row => row.Id == ending.Authorization).Status.ShouldBe(Statuses.Revoked);
		grants.Single(row => row.Id == independent.Authorization).Status.ShouldBe(Statuses.Valid);
	}

	// §10.7: two requests both pass validation for one refresh token, then redeem. Exactly one succeeds; the other answers
	// invalid_grant and ends the grant, so the winner's successor cannot refresh.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Simultaneous_load()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await StartAsync();
		var grant = await SignInAsync(host);
		var first = host.Pauses.Arm(PausePoint.BeforeRedemption);
		var firstResponse = host.RefreshAsync(grant.Tokens.RefreshToken);
		await first.Reached.WaitAsync(_pauseTimeout, Cancellation);
		var second = host.Pauses.Arm(PausePoint.BeforeRedemption);
		var secondResponse = host.RefreshAsync(grant.Tokens.RefreshToken);
		await second.Reached.WaitAsync(_pauseTimeout, Cancellation);
		(await RefreshTokenStatusAsync(host, grant)).ShouldBe(Statuses.Valid, "both passed validation; neither has redeemed");

		first.Release();
		second.Release();
		using var one = await firstResponse;
		using var other = await secondResponse;

		HttpResponseMessage[] responses = [one, other];
		var winner = responses.Where(static response => response.IsSuccessStatusCode).ShouldHaveSingleItem();
		await ShouldBeInvalidGrantAsync(responses.Single(response => response != winner));
		Ended.ShouldBe([grant.Authorization]);
		(await host.ReadGrantsAsync(grant.User.Id)).ShouldHaveSingleItem().Status.ShouldBe(Statuses.Revoked);
		using var successor = await host.RefreshAsync((await OpenIddictTestHost.ReadTokensAsync(winner, Cancellation)).RefreshToken);
		await ShouldBeInvalidGrantAsync(successor);
	}

	// §10.7: request A passes validation and pauses before redemption; request B redeems and completes (or the token is
	// self-revoked instead). A resumes, its guarded statement returns zero rows, and A answers invalid_grant and ends the
	// grant.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(LateLoads))]
	protected async Task Late_load(string late)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await StartAsync();
		var grant = await SignInAsync(host);
		var pause = host.Pauses.Arm(PausePoint.BeforeRedemption);
		var paused = host.RefreshAsync(grant.Tokens.RefreshToken);
		await pause.Reached.WaitAsync(_pauseTimeout, Cancellation);

		string? successor = null;
		if (late == Refresh)
			successor = (await RefreshAsync(host, grant.Tokens.RefreshToken)).RefreshToken;
		else
		{
			using var revoked = await host.RevokeAsync(grant.Tokens.RefreshToken);
			revoked.StatusCode.ShouldBe(HttpStatusCode.OK);
			(await RefreshTokenStatusAsync(host, grant)).ShouldBe(Statuses.Revoked, "the self-revoke landed first");
			(await host.ReadGrantsAsync(grant.User.Id)).ShouldHaveSingleItem().Status.ShouldBe(Statuses.Valid,
				"a self-revoke of a valid token ends no grant");
		}

		Ended.ShouldBeEmpty();
		pause.Release();
		using var response = await paused;

		await ShouldBeInvalidGrantAsync(response);
		Ended.ShouldBe([grant.Authorization]);
		await ShouldBeEndedAsync(host, grant);
		if (successor is null)
			return;
		using var refreshed = await host.RefreshAsync(successor);
		await ShouldBeInvalidGrantAsync(refreshed);
	}

	// §10.7: B passes validation and pauses before redemption; A redeems and pauses after redemption, before
	// GenerateRefreshToken. B resumes, loses at the guarded statement and ends the grant. A resumes and is issued a successor
	// under the revoked authorization, whose next refresh is refused, by whichever check refuses it first.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Successor_after_the_sweep()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await StartAsync();
		var grant = await SignInAsync(host);
		var beforeB = host.Pauses.Arm(PausePoint.BeforeRedemption);
		var b = host.RefreshAsync(grant.Tokens.RefreshToken);
		await beforeB.Reached.WaitAsync(_pauseTimeout, Cancellation);
		var afterA = host.Pauses.Arm(PausePoint.AfterRedemption);
		var a = host.RefreshAsync(grant.Tokens.RefreshToken);
		await afterA.Reached.WaitAsync(_pauseTimeout, Cancellation);
		(await RefreshTokenStatusAsync(host, grant)).ShouldBe(Statuses.Redeemed, "A redeemed it");

		beforeB.Release();
		using (var lost = await b)
			await ShouldBeInvalidGrantAsync(lost);
		Ended.ShouldBe([grant.Authorization]);
		(await host.ReadGrantsAsync(grant.User.Id)).ShouldHaveSingleItem().Status.ShouldBe(Statuses.Revoked);
		afterA.Release();
		using var won = await a;
		var successor = await OpenIddictTestHost.ReadTokensAsync(won, Cancellation);

		await ShouldRefuseTheSuccessorAsync(host, grant, successor);
	}

	// §10.7: the same, with B's reuse caught by EndGrantOnReuse during validation instead of at redemption: A has already
	// redeemed when B arrives, so B never reaches the redemption point.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Successor_after_reuse_at_validation()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await StartAsync();
		var grant = await SignInAsync(host);
		var afterA = host.Pauses.Arm(PausePoint.AfterRedemption);
		var a = host.RefreshAsync(grant.Tokens.RefreshToken);
		await afterA.Reached.WaitAsync(_pauseTimeout, Cancellation);
		var redemptions = host.Pauses.Passed.Count(static point => point is PausePoint.BeforeRedemption);

		using (var lost = await host.RefreshAsync(grant.Tokens.RefreshToken))
			await ShouldBeInvalidGrantAsync(lost);
		host.Pauses.Passed.Count(static point => point is PausePoint.BeforeRedemption).ShouldBe(redemptions,
			"B was refused at validation and never reached the redemption");
		Ended.ShouldBe([grant.Authorization]);
		(await host.ReadGrantsAsync(grant.User.Id)).ShouldHaveSingleItem().Status.ShouldBe(Statuses.Revoked);
		afterA.Release();
		using var won = await a;
		var successor = await OpenIddictTestHost.ReadTokensAsync(won, Cancellation);

		await ShouldRefuseTheSuccessorAsync(host, grant, successor);
	}

	// §10.7: a failure before the guarded statement is sent (a connection-open failure) answers HTTP 500, mints nothing,
	// leaves the token and the authorization valid, is not retried, and is not reuse: the same token refreshes afterward.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Definite_failure_is_a_500_and_mints_nothing()
	{
		fixture.SkipUnlessAvailable();
		RedemptionFailureInterceptor interceptor = new(RedemptionFailure.ConnectionOpen);
		await using var context = fixture.CreateContext(interceptor);
		await using var host = await StartAsync(context);
		var grant = await SignInAsync(host);
		var before = await host.ReadTokensAsync(grant.User.Id);
		interceptor.Arm();

		using (var response = await host.RefreshAsync(grant.Tokens.RefreshToken))
			response.StatusCode.ShouldBe(HttpStatusCode.InternalServerError);

		host.Failures.ShouldHaveSingleItem().ShouldBeOfType<SimulatedDbException>();
		interceptor.Fired.ShouldBe(1);
		interceptor.Opens.ShouldBe(1, "the statement is never retried");
		interceptor.Redemptions.ShouldBe(0, "the statement was never sent");
		(await host.ReadTokensAsync(grant.User.Id)).Values.ShouldBe(before.Values, ignoreOrder: true, "nothing minted, nothing changed");
		(await RefreshTokenStatusAsync(host, grant)).ShouldBe(Statuses.Valid);
		(await host.ReadGrantsAsync(grant.User.Id)).ShouldHaveSingleItem().Status.ShouldBe(Statuses.Valid);
		Ended.ShouldBeEmpty("a database failure is never reuse");
		await RefreshAsync(host, grant.Tokens.RefreshToken);
	}

	// §10.7: the statement commits and its acknowledgement is lost. The request answers HTTP 500, mints nothing, is not
	// retried and does not end the grant; the token reads redeemed, so the client's retry with it is reuse and ends the
	// grant, as the policy accepts.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Indeterminate_failure_is_a_500_and_does_not_end_the_grant()
	{
		fixture.SkipUnlessAvailable();
		RedemptionFailureInterceptor interceptor = new(RedemptionFailure.AcknowledgementLost);
		await using var context = fixture.CreateContext(interceptor);
		await using var host = await StartAsync(context);
		var grant = await SignInAsync(host);
		var before = await host.ReadTokensAsync(grant.User.Id);
		interceptor.Arm();

		using (var response = await host.RefreshAsync(grant.Tokens.RefreshToken))
			response.StatusCode.ShouldBe(HttpStatusCode.InternalServerError);

		host.Failures.ShouldHaveSingleItem().ShouldBeOfType<SimulatedDbException>();
		interceptor.Fired.ShouldBe(1);
		interceptor.Redemptions.ShouldBe(1, "the statement ran once and was never retried");
		var after = await host.ReadTokensAsync(grant.User.Id);
		after.Keys.ShouldBe(before.Keys, ignoreOrder: true, "nothing minted");
		(await RefreshTokenStatusAsync(host, grant)).ShouldBe(Statuses.Redeemed, "the redemption committed");
		(await host.ReadGrantsAsync(grant.User.Id)).ShouldHaveSingleItem().Status.ShouldBe(Statuses.Valid);
		Ended.ShouldBeEmpty("an indeterminate failure is never reuse");

		using (var retry = await host.RefreshAsync(grant.Tokens.RefreshToken))
			await ShouldBeInvalidGrantAsync(retry);
		Ended.ShouldBe([grant.Authorization]);
		await ShouldBeEndedAsync(host, grant);
	}

	// Fail-closed (Task 4.6 ruling): a code or refresh token reaching EndGrantOnReuse without a token id or an authorization
	// id is refused there (invalid_grant at the token endpoint, invalid_token, normalized to 200, at revocation), never
	// passed on to an entry check filtered out by the same missing id, and the grant that can still be named ends.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(StrippedAtValidation))]
	protected async Task A_grant_token_reaching_validation_without_an_id_is_refused_and_its_grant_ended(string stripped,
		string endpoint)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await StartAsync(configure: server => server.AddEventHandler<ValidateTokenContext>(handler => handler
			.UseInlineHandler(context =>
			{
				if (_strip && context.Principal?.HasTokenType(TokenTypeIdentifiers.RefreshToken) is true)
				{
					if (stripped == TokenId)
						context.TokenId = null;
					else
						context.AuthorizationId = null;
				}

				return ValueTask.CompletedTask;
			})
			.SetOrder(EndGrantOnReuse.Descriptor.Order - 1)));
		var grant = await SignInAsync(host);
		_strip = true;

		if (endpoint == Refresh)
			using (var response = await host.RefreshAsync(grant.Tokens.RefreshToken))
				await ShouldBeInvalidGrantAsync(response);
		else
			using (var response = await host.RevokeAsync(grant.Tokens.RefreshToken))
				response.StatusCode.ShouldBe(HttpStatusCode.OK);

		Ended.ShouldBe([grant.Authorization]);
		await ShouldBeEndedAsync(host, grant);
	}

	// Fail-closed (Task 4.6 ruling): a grant reaching the guarded redemption without a token id or an authorization id is
	// refused, never redeemed unguarded nor passed through to mint, and the grant that can still be named ends.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(StrippedAtRedemption))]
	protected async Task A_grant_reaching_redemption_without_an_id_is_refused_and_its_grant_ended(string stripped)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await StartAsync(configure: server => server.AddEventHandler<ProcessSignInContext>(handler => handler
			.UseInlineHandler(context =>
			{
				if (_strip && context.EndpointType is OpenIddictServerEndpointType.Token
					&& context.Transaction.GetProperty<ProcessAuthenticationContext>(typeof(ProcessAuthenticationContext).FullName!)
						?.RefreshTokenPrincipal is { } principal)
				{
					if (stripped == TokenId)
						principal.SetTokenId(null);
					else
						principal.SetAuthorizationId(null);
				}

				return ValueTask.CompletedTask;
			})
			.SetOrder(RedeemTokenEntryGuarded.Descriptor.Order - 1)));
		var grant = await SignInAsync(host);
		var before = (await host.ReadTokensAsync(grant.User.Id)).Count;
		_strip = true;

		using (var response = await host.RefreshAsync(grant.Tokens.RefreshToken))
			await ShouldBeInvalidGrantAsync(response);

		Ended.ShouldBe([grant.Authorization]);
		(await host.ReadTokensAsync(grant.User.Id)).Count.ShouldBe(before, "nothing minted");
		await ShouldBeEndedAsync(host, grant);
	}

	// Fail-closed (Task 4.5 review, carried): a grant whose principal reaches the token endpoint without an authorization id
	// is refused at §5.4 step 1, never minted under a fresh authorization, and the authorization its token's row links ends.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_grant_without_an_authorization_id_is_refused_at_the_token_endpoint_and_its_grant_ended()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await StartAsync(configure: server => server.AddEventHandler<ValidateTokenContext>(handler => handler
			.UseInlineHandler(context =>
			{
				if (_strip && context.Principal?.HasTokenType(TokenTypeIdentifiers.RefreshToken) is true)
					context.Principal.SetAuthorizationId(null);
				return ValueTask.CompletedTask;
			})
			.SetOrder(Protection.ValidateAuthorizationEntry.Descriptor.Order + 1)));
		var grant = await SignInAsync(host);
		var redemptions = host.Pauses.Passed.Count(static point => point is PausePoint.BeforeRedemption);
		_strip = true;

		using (var response = await host.RefreshAsync(grant.Tokens.RefreshToken))
			await ShouldBeInvalidGrantAsync(response);

		host.Pauses.Passed.Count(static point => point is PausePoint.BeforeRedemption).ShouldBe(redemptions,
			"the endpoint's step 1 refused it, so no sign-in reached the redemption");
		Ended.ShouldBe([grant.Authorization]);
		await ShouldBeEndedAsync(host, grant);
	}

	/// <summary>
	///     A host over the production composition, with the production <see cref="GrantTermination" /> behind the journal,
	///     every escaped exception answered as a 500, and, when <paramref name="redemption" /> is given, the guarded
	///     redemption's statement run on that context instead of the request's.
	/// </summary>
	Task<AuthorizeHost> StartAsync(NorseIdentityDbContext? redemption = null, Action<OpenIddictServerBuilder>? configure = null) =>
		AuthorizeHost.StartAsync(fixture, answerFailuresAs500: true, configure: builder =>
		{
			builder.Services.Replace(ServiceDescriptor.Scoped<IGrantTermination>(services =>
				new JournalingTermination(ActivatorUtilities.CreateInstance<GrantTermination>(services), _ended)));
			if (redemption is not null)
				builder.Services.Replace(ServiceDescriptor.Scoped(services =>
					ActivatorUtilities.CreateInstance<RedeemTokenEntryGuarded>(services, redemption)));
			if (configure is not null)
				builder.Services.AddOpenIddict().AddServer(configure);
		});

	/// <summary>A signed-in user's whole code flow, through the production endpoints.</summary>
	async Task<Grant> SignInAsync(AuthorizeHost host, NorseUser? user = null)
	{
		user ??= await AuthorizeHost.SeedUserAsync(fixture);
		var request = AuthorizeRequest.Create();
		var code = await host.IssueCodeAsync(request, await host.SignInAsync(user));
		using var response = await host.RedeemAsync(code, request);
		var tokens = await OpenIddictTestHost.ReadTokensAsync(response, Cancellation);
		var authorization = (await host.ReadTokensAsync(user.Id))[await host.TokenIdAsync(tokens.RefreshToken)].AuthorizationId
			.ShouldNotBeNull();
		return new(user, request, code, tokens, authorization);
	}

	static async Task<TokenSet> RefreshAsync(AuthorizeHost host, string refreshToken)
	{
		using var response = await host.RefreshAsync(refreshToken);
		return await OpenIddictTestHost.ReadTokensAsync(response, Cancellation);
	}

	static async Task<string?> RefreshTokenStatusAsync(AuthorizeHost host, Grant grant) =>
		(await host.ReadTokensAsync(grant.User.Id))[await host.TokenIdAsync(grant.Tokens.RefreshToken)].Status;

	/// <summary>The grant ended: its authorization and every one of its tokens read <c>revoked</c>.</summary>
	static async Task ShouldBeEndedAsync(AuthorizeHost host, Grant grant)
	{
		var row = (await host.ReadGrantsAsync(grant.User.Id)).Single(row => row.Id == grant.Authorization);
		row.Status.ShouldBe(Statuses.Revoked);
		row.TokenStatuses.ShouldNotBeEmpty();
		row.TokenStatuses.ShouldAllBe(static status => status == Statuses.Revoked);
	}

	/// <summary>
	///     A's successor, issued under the revoked authorization, cannot refresh: the rejection and the authorization's
	///     status are asserted, never which check refused it (§10.7).
	/// </summary>
	async Task ShouldRefuseTheSuccessorAsync(AuthorizeHost host, Grant grant, TokenSet successor)
	{
		successor.RefreshToken.ShouldNotBe(grant.Tokens.RefreshToken);
		(await host.ReadTokensAsync(grant.User.Id))[await host.TokenIdAsync(successor.RefreshToken)].AuthorizationId
			.ShouldBe(grant.Authorization, "the successor exists as a row of the revoked authorization");

		using var refreshed = await host.RefreshAsync(successor.RefreshToken);

		await ShouldBeInvalidGrantAsync(refreshed);
		(await host.ReadGrantsAsync(grant.User.Id)).ShouldHaveSingleItem().Status.ShouldBe(Statuses.Revoked);
		Ended.ShouldAllBe(ended => ended == grant.Authorization);
	}

	/// <summary>Asserts HTTP 400 and the body <c>{"error":"invalid_grant"}</c>.</summary>
	static async Task ShouldBeInvalidGrantAsync(HttpResponseMessage response)
	{
		response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
		using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(Cancellation));
		body.RootElement.EnumerateObject().Select(static member => (member.Name, member.Value.GetString()))
			.ShouldBe([(Parameters.Error, Errors.InvalidGrant)]);
	}

	/// <summary>A completed code flow: the user, its authorize request and code, the tokens, and its one authorization.</summary>
	sealed record Grant(NorseUser User, AuthorizeRequest Request, string Code, TokenSet Tokens, Guid Authorization);

	/// <summary>The production termination, journaling every authorization it is asked to end first.</summary>
	sealed class JournalingTermination(IGrantTermination inner, ConcurrentQueue<Guid> ended) : IGrantTermination
	{
		public Task<GrantEnd> EndAsync(Guid authorizationId, CancellationToken cancellationToken)
		{
			ended.Enqueue(authorizationId);
			return inner.EndAsync(authorizationId, cancellationToken);
		}
	}

	/// <summary>Where a <see cref="RedemptionFailureInterceptor" /> fails the guarded statement.</summary>
	enum RedemptionFailure
	{
		/// <summary>Not a mode.</summary>
		None = 0,

		/// <summary>The connection the statement would run on fails to open: nothing is sent, so the failure is definite.</summary>
		ConnectionOpen = 1,

		/// <summary>The statement ran and committed (it runs outside any transaction), and the acknowledgement is then lost.</summary>
		AcknowledgementLost = 2
	}

	/// <summary>
	///     Fails the guarded redemption once armed, on the context the redemption alone runs on. Not
	///     <see cref="CommitFailureInterceptor" />: the guarded statement is one autocommitted statement with no transaction,
	///     so no commit hook ever sees it; the lost acknowledgement is the statement's own.
	/// </summary>
	sealed class RedemptionFailureInterceptor(RedemptionFailure mode) : DbConnectionInterceptor, IDbCommandInterceptor
	{
		int _armed;
		int _fired;
		int _opens;
		int _redemptions;

		/// <summary>How many times the failure was injected: one, or the fact proved nothing.</summary>
		public int Fired => Volatile.Read(ref _fired);

		/// <summary>How many connection opens were attempted once armed.</summary>
		public int Opens => Volatile.Read(ref _opens);

		/// <summary>How many guarded statements executed once armed.</summary>
		public int Redemptions => Volatile.Read(ref _redemptions);

		/// <summary>Fail the next redemption, and count from here.</summary>
		public void Arm() =>
			Volatile.Write(ref _armed, 1);

		public override ValueTask<InterceptionResult> ConnectionOpeningAsync(DbConnection connection, ConnectionEventData eventData,
			InterceptionResult result, CancellationToken cancellationToken = default)
		{
			if (Volatile.Read(ref _armed) is 1)
				Interlocked.Increment(ref _opens);
			return mode is RedemptionFailure.ConnectionOpen && Fire() ?
				throw new SimulatedDbException("Simulated failure to open the connection: the statement was never sent.") :
				ValueTask.FromResult(result);
		}

		public ValueTask<int> NonQueryExecutedAsync(DbCommand command, CommandExecutedEventData eventData, int result,
			CancellationToken cancellationToken = default)
		{
			if (Volatile.Read(ref _armed) is not 1 || !command.CommandText.Contains("'redeemed'", StringComparison.Ordinal))
				return ValueTask.FromResult(result);

			Interlocked.Increment(ref _redemptions);
			return mode is RedemptionFailure.AcknowledgementLost && Fire() ?
				throw new SimulatedDbException("Simulated loss of the redemption's acknowledgement: the statement committed.") :
				ValueTask.FromResult(result);
		}

		bool Fire() =>
			Volatile.Read(ref _armed) is 1 && Interlocked.CompareExchange(ref _fired, 1, 0) is 0;
	}
}
