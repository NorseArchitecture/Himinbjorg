using System.Net;
using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Norse.AuthN.Services;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.Passkeys;
using Norse.Identity.Web.Server.Tests.OpenIddict;
using Norse.Identity.Web.Server.TwoFactor;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The lanes and audiences across this realm's operations (2026-10-29 OpenIddict spec §7.5, §10.12), once per provider,
///     over <see cref="GrpcSurfaceHost" /> with real user and machine tokens from the production endpoints: a user bearer is
///     refused by every <see cref="AuthNPolicies.Account" /> operation and by the <see cref="AuthNPolicies.Public" />
///     operations it would otherwise succeed at, alone and beside a valid identity cookie, and reaches the two read
///     operations; a machine token is refused by every user-facing policy; a user token is refused by the façade.
/// </summary>
/// <remarks>Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" /> records.</remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class LaneAdmissionSuite(IdentityFixture fixture)
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	const int Ok = 0;

	/// <summary>
	///     The gate. True here, which is right for Postgres; a provider class whose container a host cannot run hides it with
	///     its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <summary>Whether the bearer travels beside a valid identity cookie.</summary>
	public static TheoryData<bool> WithCookie => [false, true];

	/// <summary>Every operation the account policy admits, read off the services' own endpoint metadata.</summary>
	static GrpcOperation[] AccountOperations =>
	[
		.. new[] { (typeof(AccountService), typeof(IAccountService)), (typeof(TwoFactorService), typeof(ITwoFactorService)), (typeof(PasskeyService), typeof(IPasskeyService)) }
			.SelectMany(static pair => pair.Item1.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly)
				.Where(static method => method.GetCustomAttribute<AuthorizeAttribute>()?.Policy == AuthNPolicies.Account)
				.Select(method => new GrpcOperation(pair.Item2, method.Name)))
	];

	static GrpcOperation ForgotPassword => new(typeof(IAuthenticationService), nameof(IAuthenticationService.ForgotPassword));

	static GrpcOperation GetSignInMethods => new(typeof(ISignInMethodsService), nameof(ISignInMethodsService.GetSignInMethods));

	static GrpcOperation GetAccountStatus => new(typeof(IAccountService), nameof(IAccountService.GetAccountStatus));

	static GrpcOperation GetMyPersonalData => new(typeof(IIdentityService), nameof(IIdentityService.GetMyPersonalDataAsync));

	static GrpcOperation GetExternalLogins => new(typeof(IAccountService), nameof(IAccountService.GetExternalLogins));

	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(WithCookie))]
	protected async Task User_bearer_is_refused_by_every_account_operation(bool withCookie)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await GrpcSurfaceHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var cookie = await host.Host.SignInAsync(user);
		var bearer = await host.MintUserTokenAsync(cookie);

		AccountOperations.Length.ShouldBe(20, "eight account, seven two-factor and six passkey operations, less GetAccountStatus");
		foreach (var operation in AccountOperations)
		{
			var answer = await host.CallAsync(operation, cookie: withCookie ? cookie : null, bearer: bearer);

			answer.Http.ShouldBe(HttpStatusCode.Forbidden, operation.ToString());
			answer.Details.ShouldBeNull(operation.ToString());
		}

		// The cookie alone still reaches the same door: the refusal is the bearer's lane, not the operation.
		(await host.CallAsync(GetExternalLogins, cookie: cookie)).Status.ShouldBe(Ok);
	}

	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[MemberData(nameof(WithCookie))]
	protected async Task User_bearer_is_refused_by_forgot_password_and_get_sign_in_methods(bool withCookie)
	{
		fixture.SkipUnlessAvailable();
		await using var host = await GrpcSurfaceHost.StartAsync(fixture);
		var user = await GrpcSurfaceHost.SeedConfirmedUserAsync(fixture);
		var cookie = await host.Host.SignInAsync(user);
		var bearer = await host.MintUserTokenAsync(cookie);
		ForgotPasswordRequest forgot = new() { EmailInput = user.Email! };

		var refusedForgot = await host.CallAsync(ForgotPassword, forgot, withCookie ? cookie : null, bearer);
		var refusedMethods = await host.CallAsync(GetSignInMethods, new GetSignInMethodsRequest(), withCookie ? cookie : null, bearer);

		refusedForgot.Http.ShouldBe(HttpStatusCode.Forbidden);
		refusedMethods.Http.ShouldBe(HttpStatusCode.Forbidden);
		host.Emails.Sent.ShouldBeEmpty("a refused ForgotPassword sends nothing");

		// A cookie caller still reaches both, and the same ForgotPassword sends the one email the bearer could not.
		(await host.CallAsync(ForgotPassword, forgot, cookie)).Status.ShouldBe(Ok);
		(await host.CallAsync(GetSignInMethods, new GetSignInMethodsRequest(), cookie)).Status.ShouldBe(Ok);
		host.Emails.Sent.ShouldBe([user.Email!]);
	}

	// PF7: GetAccountStatus is admitted by AccountRead alone, end to end over gRPC, as is disclosure's Self.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task User_bearer_reaches_get_my_personal_data_and_get_account_status()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await GrpcSurfaceHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var bearer = await host.MintUserTokenAsync(await host.Host.SignInAsync(user));

		var data = await host.CallAsync(GetMyPersonalData, new GetMyPersonalDataRequest(), bearer: bearer);
		var status = await host.CallAsync(GetAccountStatus, bearer: bearer);

		data.Read<PersonalDataResponse>().Email.ShouldBe(user.Email);
		status.Read<AccountStatusResponse>().HasPassword.ShouldBeTrue();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Machine_token_is_refused_by_self_account_read_account_and_public()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await GrpcSurfaceHost.StartAsync(fixture);
		var machine = await host.MintMachineTokenAsync();

		(await host.GetFacadeAsync(machine)).ShouldBe(HttpStatusCode.OK, "the token is a working machine token");
		// Buvy's lane ruling: a machine token on the gRPC (User) lane fails authentication, so the refusal is the bare
		// challenge, never a forbid.
		ShouldBeBare401(await host.CallAsync(GetMyPersonalData, new GetMyPersonalDataRequest(), bearer: machine));
		ShouldBeBare401(await host.CallAsync(GetAccountStatus, bearer: machine));
		ShouldBeBare401(await host.CallAsync(GetExternalLogins, bearer: machine));
		ShouldBeBare401(await host.CallAsync(GetSignInMethods, new GetSignInMethodsRequest(), bearer: machine));
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task User_token_is_refused_by_machine()
	{
		fixture.SkipUnlessAvailable();
		await using var host = await GrpcSurfaceHost.StartAsync(fixture);
		var user = await AuthorizeHost.SeedUserAsync(fixture);
		var bearer = await host.MintUserTokenAsync(await host.Host.SignInAsync(user));

		// Buvy's lane ruling: a user token on the façade (Machine) lane fails authentication: the bare challenge.
		ShouldBeBare401(await host.GetFacadeAnswerAsync(bearer));
		(await host.GetFacadeAsync(await host.MintMachineTokenAsync())).ShouldBe(HttpStatusCode.OK, "the façade admits a machine token");
	}

	/// <summary>
	///     The composed authentication-challenge shape: HTTP 401, no redirect, no body, and one <c>WWW-Authenticate:
	///     Bearer</c> carrying at most <c>error="invalid_token"</c>, never a description or a URI.
	/// </summary>
	static void ShouldBeBare401(GrpcAnswer answer)
	{
		answer.Http.ShouldBe(HttpStatusCode.Unauthorized);
		answer.Location.ShouldBeNull();
		answer.Body.ShouldBeEmpty();
		var challenge = answer.Challenges.ShouldHaveSingleItem();
		challenge.Scheme.ShouldBe("Bearer");
		challenge.Parameter.ShouldBeOneOf([null, "error=\"invalid_token\""], "at most the bare error, never a description or a URI");
	}
}
