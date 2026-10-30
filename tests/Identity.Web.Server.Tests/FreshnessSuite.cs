using System.Net;
using Microsoft.AspNetCore.Http;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Tests.OpenIddict;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     Recent authentication on the four gated operations (2026-10-29 OpenIddict spec §6.3, §10.11; plan rulings T4-3, T4-4,
///     PF4), once per provider, over <see cref="GrpcSurfaceHost" />: a stale caller of each of the five commands is answered
///     <see cref="ErrorCategory.Forbidden" /> with <see cref="NorseErrorCodes.ReauthenticationRequired" /> and the
///     server-authored <c>NextUrl</c>, over the wire, and nothing happens; the link start redirects to the same shape instead;
///     a fresh caller passes; every other refusal stays a bare 403.
/// </summary>
/// <remarks>
///     Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" /> records.
///     Staleness is the host's clock moved past the default 10-minute window after the sign-in stamped <c>auth_time</c>.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class FreshnessSuite(IdentityFixture fixture)
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	const string LinkStart = "/Account/Manage/LinkExternalLogin?provider=Unknown";

	static readonly TimeSpan _pastTheWindow = TimeSpan.FromMinutes(10) + TimeSpan.FromSeconds(1);

	/// <summary>The gated operations: the gRPC call, the wire request and the hop's landing.</summary>
	static readonly Dictionary<string, (GrpcOperation Operation, object? Request, string NextUrl, int FreshStatus)> _gated =
		new(StringComparer.Ordinal)
		{
			["GetPasskeyCreationOptions"] = (new(typeof(IPasskeyService), nameof(IPasskeyService.GetPasskeyCreationOptions)), null,
				"/Account/Login?returnUrl=%2FAccount%2FManage%2FPasskeys", Ok),
			// An empty request fails validation, which runs after authorization: a fresh caller reaches it.
			["AddPasskey"] = (new(typeof(IPasskeyService), nameof(IPasskeyService.AddPasskey)), new AddPasskeyRequest(),
				"/Account/Login?returnUrl=%2FAccount%2FManage%2FPasskeys", InvalidArgument),
			// The fresh caller never enabled two-factor, which the handler answers as Validation.
			["DisableTwoFactor"] = (new(typeof(ITwoFactorService), nameof(ITwoFactorService.DisableTwoFactor)), null,
				"/Account/Login?returnUrl=%2FAccount%2FManage%2FDisable2fa", InvalidArgument),
			["GetAuthenticatorSetup"] = (new(typeof(ITwoFactorService), nameof(ITwoFactorService.GetAuthenticatorSetup)), null,
				"/Account/Login?returnUrl=%2FAccount%2FManage%2FEnableAuthenticator", Ok),
			["ResetAuthenticator"] = (new(typeof(ITwoFactorService), nameof(ITwoFactorService.ResetAuthenticator)), null,
				"/Account/Login?returnUrl=%2FAccount%2FManage%2FResetAuthenticator", Ok)
		};

	const int Ok = 0;
	const int InvalidArgument = 3;
	const int PermissionDenied = 7;

	/// <summary>
	///     The gate. True here, which is right for Postgres; a provider class whose container a host cannot run hides it with
	///     its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <summary>Every gated operation, by name.</summary>
	public static TheoryData<string> GatedOperations => [.. _gated.Keys];

	/// <summary>The link start's hop under the root and under a path base (PF4: built exactly as Midgard builds the mediator's).</summary>
	public static TheoryData<string, string> LinkStartHops =>
		new()
		{
			{ "", "/Account/Login?returnUrl=%2FAccount%2FManage%2FExternalLogins" },
			{ "/app", "/app/Account/Login?returnUrl=%2Fapp%2FAccount%2FManage%2FExternalLogins" }
		};

	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(GatedOperations))]
	protected async Task Each_gated_operation_answers_reauthentication_required_when_stale(string name)
	{
		fixture.SkipUnlessAvailable();
		var (operation, request, nextUrl, _) = _gated[name];
		await using var host = await GrpcSurfaceHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.Host.SignInAsync(user);
		var stamp = await StampAsync(user);
		host.Host.Clock.Advance(_pastTheWindow);

		var answer = await host.CallAsync(operation, request, cookie);

		answer.Http.ShouldBe(HttpStatusCode.OK, "the endpoint edge admits the caller: freshness rides the command alone");
		answer.Status.ShouldBe(PermissionDenied);
		var error = answer.Error.ShouldNotBeNull();
		error.Reason.ShouldBe(nameof(ErrorCategory.Forbidden));
		error.Metadata["code"].ShouldBe(NorseErrorCodes.ReauthenticationRequired);
		error.Metadata["nextUrl"].ShouldBe(nextUrl);
		(await StampAsync(user)).ShouldBe(stamp, "the handler never ran");
	}

	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(GatedOperations))]
	protected async Task A_fresh_caller_passes(string name)
	{
		fixture.SkipUnlessAvailable();
		var (operation, request, _, freshStatus) = _gated[name];
		await using var host = await GrpcSurfaceHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.Host.SignInAsync(user);
		// Inside the window: auth_time is whole seconds, so a full ten minutes would read a fraction of a second past it.
		host.Host.Clock.Advance(TimeSpan.FromMinutes(9));

		var answer = await host.CallAsync(operation, request, cookie);

		answer.Http.ShouldBe(HttpStatusCode.OK);
		answer.Status.ShouldBe(freshStatus, answer.Error?.ToString());
		answer.Error?.Metadata.ContainsKey("code").ShouldBeFalse();
	}

	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(LinkStartHops))]
	protected async Task The_link_start_redirects_when_stale(string pathBase, string hop)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await GrpcSurfaceHost.StartAsync(fixture, new PathString(pathBase.Length == 0 ? null : pathBase));
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.Host.SignInAsync(user);
		host.Host.Clock.Advance(_pastTheWindow);

		using var response = await GetLinkStartAsync(host, cookie);

		response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
		response.Headers.Location.ShouldNotBeNull().OriginalString.ShouldBe(hop);
	}

	// A fresh caller reaches the start itself, which refuses the unknown provider with its own failed-status redirect.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_fresh_caller_reaches_the_link_start()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await GrpcSurfaceHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.Host.SignInAsync(user);

		using var response = await GetLinkStartAsync(host, cookie);

		response.StatusCode.ShouldBe(HttpStatusCode.Redirect);
		response.Headers.Location.ShouldNotBeNull().OriginalString
			.ShouldBe("/Account/Manage/ExternalLogins?status=external-login-failed");
	}

	// The operation policy is evaluated first, at the edge and in the mediator: a user bearer fails Account's lane and is
	// refused bare, never handed the hop, however stale its auth_time.
	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(GatedOperations))]
	protected async Task Other_failures_stay_bare(string name)
	{
		fixture.SkipUnlessAvailable();
		var (operation, request, _, _) = _gated[name];
		await using var host = await GrpcSurfaceHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var bearer = await host.MintUserTokenAsync(await host.Host.SignInAsync(user));

		var answer = await host.CallAsync(operation, request, bearer: bearer);

		answer.Http.ShouldBe(HttpStatusCode.Forbidden);
		answer.Details.ShouldBeNull();
		answer.Location.ShouldBeNull();
	}

	// The link start's other failure: no identity, so the anonymous principal fails Account, and a non-navigation is
	// answered a bare 403, never the hop.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Other_failures_stay_bare_at_the_link_start()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await GrpcSurfaceHost.StartAsync(fixture);

		using var response = await GetLinkStartAsync(host, cookie: null);

		response.StatusCode.ShouldBe(HttpStatusCode.Forbidden);
		response.Headers.Location.ShouldBeNull();
	}

	static async Task<HttpResponseMessage> GetLinkStartAsync(GrpcSurfaceHost host, string? cookie)
	{
		using HttpRequestMessage request = new(HttpMethod.Get, new Uri(host.Host.PathBase + LinkStart, UriKind.Relative));
		request.Headers.Add("Sec-Fetch-Site", "same-origin");
		if (cookie is not null)
			request.Headers.Add("Cookie", cookie);
		return await host.Host.SendAsync(request);
	}

	async Task<string?> StampAsync(NorseUser user)
	{
		var userManager = fixture.CreateUserManager();
		return await userManager.GetSecurityStampAsync((await userManager.FindByIdAsync(user.Id.ToString())).ShouldNotBeNull());
	}
}
