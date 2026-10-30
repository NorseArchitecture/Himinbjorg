using System.Diagnostics.Metrics;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.Metrics.Testing;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Testing;
using Microsoft.Extensions.Options;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.OpenIddict;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>
///     The production <c>EndGrant</c> (2026-10-29 OpenIddict spec §5.5, §10.7 "<c>EndGrant</c> failure"; plan Task 4.5),
///     once per provider, over <see cref="AuthorizeHost" /> with <see cref="GrantTermination" /> built over an injected
///     failure: step 1 (the authorization's revocation, the durable boundary) is retried up to three times and counts any
///     exception as a failed attempt; step 2 (its tokens) runs only after a confirmed step 1 and is hygiene.
/// </summary>
/// <remarks>
///     Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///     records: xUnit discovers them on each <see langword="sealed" /> provider class.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class GrantTerminationSuite(IdentityFixture fixture)
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	/// <summary>A fragment only step 1's statement carries.</summary>
	const string StepOneMarker = "= 'revoked'";

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	// §10.7: step 1 failing on every attempt is unconfirmed: three attempts, one Error naming only the authorization, the
	// counter once, step 2 never run, and the presented grant still refused.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Step_one_failing_every_attempt_is_unconfirmed()
	{
		fixture.SkipUnlessAvailable();
		FailingCommandInterceptor interceptor = new(StepOneMarker, failures: 10);
		await using var context = fixture.CreateContext(interceptor);
		await using var host = await StartAsync(sp => ActivatorUtilities.CreateInstance<GrantTermination>(sp, context));
		using var counter = Counter(host);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var request = AuthorizeRequest.Create();
		var code = await host.IssueCodeAsync(request, await host.SignInAsync(user));
		await RotateStampAsync(user);

		using var response = await host.RedeemAsync(code, request);

		response.StatusCode.ShouldBe(HttpStatusCode.BadRequest, "the rejection is still sent");
		(await response.Content.ReadAsStringAsync(Cancellation)).ShouldContain(Errors.InvalidGrant);
		interceptor.Fired.ShouldBe(3, "step 1 is attempted three times, never more");
		var grant = (await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem();
		grant.Status.ShouldBe(Statuses.Valid, "no attempt landed");
		grant.TokenStatuses.ShouldAllBe(static status => status == Statuses.Valid, "step 2 never runs unconfirmed");
		var error = Records(host).Where(static record => record.Level == LogLevel.Error).ShouldHaveSingleItem();
		error.Id.ShouldBe(new EventId(GrantTermination.UnconfirmedEventId, "GrantEndUnconfirmed"));
		error.StructuredState.ShouldNotBeNull()
			.Where(static pair => pair.Key != "{OriginalFormat}")
			.ShouldBe([new("AuthorizationId", grant.Id.ToString())]);
		counter.GetMeasurementSnapshot().ShouldHaveSingleItem().Value.ShouldBe(1);
	}

	// Any exception is a failed attempt, so a later attempt that lands confirms the end: nothing is surfaced, and step 2 runs.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Step_one_landing_on_a_later_attempt_is_confirmed()
	{
		fixture.SkipUnlessAvailable();
		FailingCommandInterceptor interceptor = new(StepOneMarker, failures: 2);
		await using var context = fixture.CreateContext(interceptor);
		await using var host = await StartAsync(sp => ActivatorUtilities.CreateInstance<GrantTermination>(sp, context));
		using var counter = Counter(host);
		var (user, _) = await SignInAsync(host);
		var authorization = (await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem().Id;

		(await EndAsync(host, authorization)).ShouldBe(GrantEnd.Confirmed);

		interceptor.Fired.ShouldBe(2);
		var grant = (await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem();
		grant.Status.ShouldBe(Statuses.Revoked);
		grant.TokenStatuses.ShouldAllBe(static status => status == Statuses.Revoked);
		Records(host).ShouldNotContain(static record => record.Level >= LogLevel.Warning);
		counter.GetMeasurementSnapshot().ShouldBeEmpty();
	}

	// Step 1 is idempotent: an authorization already revoked matches no row, and that is still a confirmed end.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Zero_rows_on_an_authorization_already_revoked_is_confirmed()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var (user, _) = await SignInAsync(host);
		var authorization = (await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem().Id;

		(await EndAsync(host, authorization)).ShouldBe(GrantEnd.Confirmed);
		(await EndAsync(host, authorization)).ShouldBe(GrantEnd.Confirmed);

		(await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem().Status.ShouldBe(Statuses.Revoked);
	}

	// §10.7: step 2 failing after a confirmed step 1 logs a Warning and leaves the authorization revoked, so none of its
	// tokens, still unrevoked, can be redeemed.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Step_two_failing_after_confirmation_leaves_the_authorization_revoked()
	{
		fixture.SkipUnlessAvailable();
		var tokens = Substitute.For<IOpenIddictTokenManager>();
		tokens.RevokeByAuthorizationIdAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
			.Returns(static _ => ValueTask.FromException<long>(new SimulatedDbException("Simulated failure of step 2.")));
		await using var host = await StartAsync(sp => ActivatorUtilities.CreateInstance<GrantTermination>(sp, tokens));
		using var counter = Counter(host);
		var (user, refreshToken) = await SignInAsync(host);
		var authorization = (await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem().Id;

		(await EndAsync(host, authorization)).ShouldBe(GrantEnd.Confirmed);

		var grant = (await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem();
		grant.Status.ShouldBe(Statuses.Revoked);
		grant.TokenStatuses.ShouldContain(Statuses.Valid, "step 2 failed, so the live refresh token was never revoked");
		var warning = Records(host).Where(static record => record.Level >= LogLevel.Warning).ShouldHaveSingleItem();
		warning.Level.ShouldBe(LogLevel.Warning);
		warning.Id.Id.ShouldBe(GrantTermination.TokensNotRevokedEventId);
		counter.GetMeasurementSnapshot().ShouldBeEmpty("the boundary was confirmed");

		using var refreshed = await host.RefreshAsync(refreshToken);

		refreshed.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
		(await refreshed.Content.ReadAsStringAsync(Cancellation)).ShouldContain(Errors.InvalidGrant);
	}

	// M2: the reads that decide whether a grant ends ignore the request's cancellation, as step 1 does. Here the reuse read:
	// a redeemed code presented by a client that has already hung up still ends its grant.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_hang_up_never_stops_the_reuse_read_from_ending_the_grant()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var (user, _) = await SignInAsync(host);
		var code = (await host.ReadTokensAsync(user.Id)).Values
			.Single(static token => token.Type == TokenTypeIdentifiers.Private.AuthorizationCode);
		code.Status.ShouldBe(Statuses.Redeemed);
		OpenIddictTestHost.RecordingGrantTermination termination = new();
		await using var scope = host.Services.CreateAsyncScope();
		var context = HungUpValidation(scope.ServiceProvider, code.Id, code.AuthorizationId);

		await new EndGrantOnReuse(scope.ServiceProvider.GetRequiredService<NorseIdentityDbContext>(), termination)
			.HandleAsync(context);

		termination.Ended.ShouldBe([code.AuthorizationId!.Value]);
		context.IsRejected.ShouldBeTrue();
	}

	// M2, the link read: an unanchored grant (no authorization id) presented by a client that has hung up still ends the
	// grant its token's row links.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_hang_up_never_stops_the_link_read_from_ending_an_unanchored_grant()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture);
		var (user, refreshToken) = await SignInAsync(host);
		var token = await host.TokenIdAsync(refreshToken);
		var authorization = (await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem().Id;
		OpenIddictTestHost.RecordingGrantTermination termination = new();
		await using var scope = host.Services.CreateAsyncScope();

		await UnanchoredGrant.EndAsync(scope.ServiceProvider.GetRequiredService<NorseIdentityDbContext>(), termination,
			token.ToString(), authorizationId: null, new CancellationToken(canceled: true));

		termination.Ended.ShouldBe([authorization]);
	}

	// M2, the user read: a stamp-rotated grant presented by a client that hangs up before the exchange re-reads the user
	// still ends (the request itself may then fail; the end is what matters).
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_hang_up_never_stops_the_user_read_from_ending_a_stamp_rotated_grant()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await AuthorizeHost.StartAsync(fixture, answerFailuresAs500: true, map: static app => app.Use(
			static (HttpContext context, RequestDelegate next) =>
			{
				// After OpenIddict validated the request, before the exchange endpoint runs: the client has hung up.
				if (context.Request.Path == AuthorizeHost.TokenPath)
					context.RequestAborted = new(canceled: true);
				return next(context);
			}));
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var request = AuthorizeRequest.Create();
		var code = await host.IssueCodeAsync(request, await host.SignInAsync(user));
		await RotateStampAsync(user);

		using var response = await host.RedeemAsync(code, request);

		(await host.ReadGrantsAsync(user.Id)).ShouldHaveSingleItem().Status
			.ShouldBe(Statuses.Revoked, $"the grant ended despite the hang-up ({response.StatusCode})");
	}

	Task<AuthorizeHost> StartAsync(Func<IServiceProvider, IGrantTermination> termination) =>
		AuthorizeHost.StartAsync(fixture, configure: builder => builder.Services
			.AddFakeLogging()
			.Replace(ServiceDescriptor.Scoped(termination)));

	/// <summary>A signed-in user's whole code flow: the user and the refresh token its code was redeemed for.</summary>
	async Task<(NorseUser User, string RefreshToken)> SignInAsync(AuthorizeHost host)
	{
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var request = AuthorizeRequest.Create();
		using var response = await host.RedeemAsync(await host.IssueCodeAsync(request, await host.SignInAsync(user)), request);
		return (user, (await OpenIddictTestHost.ReadTokensAsync(response, Cancellation)).RefreshToken);
	}

	static async Task<GrantEnd> EndAsync(AuthorizeHost host, Guid authorization)
	{
		await using var scope = host.Services.CreateAsyncScope();
		return await scope.ServiceProvider.GetRequiredService<IGrantTermination>().EndAsync(authorization, Cancellation);
	}

	async Task RotateStampAsync(NorseUser user)
	{
		var userManager = fixture.CreateUserManager();
		(await userManager.UpdateSecurityStampAsync((await userManager.FindByIdAsync(user.Id.ToString())).ShouldNotBeNull()))
			.Succeeded.ShouldBeTrue();
	}

	/// <summary>A token-endpoint validation of a code whose request is already cancelled: the client has hung up.</summary>
	static ValidateTokenContext HungUpValidation(IServiceProvider services, Guid tokenId, Guid? authorizationId) =>
		new(new()
		{
			CancellationToken = new(canceled: true),
			EndpointType = OpenIddictServerEndpointType.Token,
			Options = services.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue,
			ServiceProvider = services
		})
		{
			TokenId = tokenId.ToString(),
			AuthorizationId = authorizationId?.ToString()
		};

	static MetricCollector<long> Counter(AuthorizeHost host) =>
		new(host.Services.GetRequiredService<IMeterFactory>(), GrantTermination.MeterName, GrantTermination.UnconfirmedCounterName);

	static IEnumerable<FakeLogRecord> Records(AuthorizeHost host) =>
		host.Services.GetFakeLogCollector().GetSnapshot()
			.Where(static record => record.Category == typeof(GrantTermination).FullName);
}
