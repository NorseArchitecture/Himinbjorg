using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Norse.Abstractions.Components.Authorization;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.OpenIddict;
using Norse.Identity.Web.Server.Tests.Passkeys;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The <c>norse_reauth</c> binding at the stamp point (spec §5.2 "The binding", §10.4 "Binding, positive" and "two-factor
///     plumbing", T4-1), over <see cref="TwoFactorHarness" />'s real pipeline: each of the five credential paths signs in
///     with an authorize request as its landing, exactly as its handler parks it (<see cref="ParkedReturnUrl" />), and
///     either writes the cookie on its own request or, on a circuit, stashes it through Midgard's real
///     <see cref="Norse.Abstractions.Web.Server.DeferredSignIn.IDeferredSignIn" /> for the <c>/_auth/complete</c> hop to
///     write. The cookie the browser ends up holding is decrypted and read. Halting gate H5 is the first theory.
/// </summary>
public sealed class ReauthBindingTests
{
	const string ApplicationCookie = ".AspNetCore.Identity.Application";
	const string CredentialJson = "{\"id\":\"credential\"}";
	const string RawAssertionState = "{\"challenge\":\"raw-assertion-state\",\"userId\":null}";
	static readonly string _scheme = IdentityConstants.ApplicationScheme;

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	/// <summary>The five credential paths (spec §6.1), each immediate and deferred through <c>/_auth/complete</c>.</summary>
	public static TheoryData<string, bool> CredentialPaths => new()
	{
		{ "password", false }, { "password", true },
		{ "authenticator", false }, { "authenticator", true },
		{ "recovery code", false }, { "recovery code", true },
		{ "passkey", false }, { "passkey", true },
		{ "external login", false }, { "external login", true }
	};

	/// <summary>The three paths that complete through the two-factor challenge.</summary>
	public static TheoryData<string> ChallengePaths => ["authenticator", "recovery code", "external login"];

	/// <summary>Every path, with its sign-in succeeding and throwing.</summary>
	public static TheoryData<string, bool> SlotCases => new()
	{
		{ "password", false }, { "password", true },
		{ "authenticator", false }, { "authenticator", true },
		{ "recovery code", false }, { "recovery code", true },
		{ "passkey", false }, { "passkey", true },
		{ "external login", false }, { "external login", true }
	};

	// H5: every path reaches the stamp point with its landing, and the cookie the browser holds afterward is bound.
	[Theory]
	[MemberData(nameof(CredentialPaths))]
	async Task Each_credential_path_stamps_the_marker_id(string path, bool deferred)
	{
		using var harness = await TwoFactorHarness.StartAsync(realDeferredSignIn: true);
		var marker = Mint(harness, harness.User.Id);

		var probe = await SignInAsync(harness, path, Landing(harness, marker), deferred);

		probe.Exception.ShouldBeNull();
		probe.Value.ShouldBeTrue("the sign-in succeeded");
		ShouldBeBoundTo(await CookiePrincipalAsync(harness, probe, deferred), marker);
	}

	[Theory]
	[MemberData(nameof(SlotCases))]
	async Task Two_factor_landing_is_on_the_slot_during_sign_in_and_gone_after(string path, bool signInThrows)
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var landing = Landing(harness, Mint(harness, harness.User.Id));
		InvalidOperationException thrown = new("The sign-in failed.");
		var accessor = harness.Services.GetRequiredService<IHttpContextAccessor>();
		List<object?> during = [];
		bool? presentAfter = null;
		// The claims factory runs inside SignInWithClaimsAsync, after the stamp point has read the slot.
		harness.ClaimsFactory.CreateAsync(harness.User).Returns(_ =>
		{
			during.Add(accessor.HttpContext!.Items[NorseSignInManager.ReauthLandingItemName]);
			return signInThrows ?
				throw thrown :
				new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, harness.UserId)], _scheme));
		});

		var probe = await SignInAsync(harness, path, landing, deferred: false, after: manager =>
			presentAfter = manager.Context.Items.ContainsKey(NorseSignInManager.ReauthLandingItemName));

		if (signInThrows)
			probe.Exception.ShouldBeSameAs(thrown);
		else
			probe.Value.ShouldBeTrue();
		during.ShouldBe([landing], "the stamp point's one sign-in saw the landing on the slot");
		presentAfter.ShouldBe(false);
	}

	[Theory]
	[MemberData(nameof(ChallengePaths))]
	async Task Complete_two_factor_returns_the_landing_unchanged(string path)
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var landing = Landing(harness, Mint(harness, harness.User.Id));
		var token = await MintChallengeAsync(harness, path, landing);

		var completed = await harness.RunAsync(manager => Complete(manager, path, token));

		completed.Exception.ShouldBeNull();
		var result = completed.Value.ShouldNotBeNull();
		result.Result.Succeeded.ShouldBeTrue();
		result.ReturnUrl.ShouldBe(landing);
	}

	[Theory]
	[InlineData("password")]
	[InlineData("authenticator")]
	async Task An_expired_marker_stamps_nothing(string path)
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var landing = Landing(harness, Mint(harness, harness.User.Id));
		harness.Clock.Advance(ReauthMarkers.Lifetime);

		await ShouldStampNothingAsync(harness, path, landing);
	}

	[Theory]
	[InlineData("garbage")]
	[InlineData("another key ring")]
	[InlineData("two markers")]
	[InlineData("upper-cased name")]
	[InlineData("mixed-cased name")]
	async Task An_invalid_marker_stamps_nothing(string kind)
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var landing = kind switch
		{
			"garbage" => "/connect/authorize?client_id=norse&norse_reauth=not-a-marker",
			"another key ring" => "/connect/authorize?client_id=norse&norse_reauth="
				+ new ReauthMarkers(new EphemeralDataProtectionProvider(), harness.Clock)
					.Protect(Mint(harness, harness.User.Id)),
			"two markers" => Landing(harness, Mint(harness, harness.User.Id)) + "&norse_reauth="
				+ Markers(harness).Protect(Mint(harness, harness.User.Id)),
			"upper-cased name" => Landing(harness, Mint(harness, harness.User.Id))
				.Replace("norse_reauth=", "NORSE_REAUTH=", StringComparison.Ordinal),
			"mixed-cased name" => Landing(harness, Mint(harness, harness.User.Id))
				.Replace("norse_reauth=", "Norse_Reauth=", StringComparison.Ordinal),
			_ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null)
		};

		await ShouldStampNothingAsync(harness, "password", landing);
	}

	[Theory]
	[InlineData("password")]
	[InlineData("authenticator")]
	async Task A_marker_for_another_user_stamps_nothing(string path)
	{
		using var harness = await TwoFactorHarness.StartAsync();

		await ShouldStampNothingAsync(harness, path, Landing(harness, Mint(harness, Guid.NewGuid())));
	}

	// Spec §5.2: a marker minted for an anonymous challenge names no user and binds whoever presents the credential.
	[Theory]
	[InlineData("password")]
	[InlineData("authenticator")]
	async Task An_anonymous_marker_binds_whoever_signs_in(string path)
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var marker = Mint(harness, userId: null);

		var probe = await SignInAsync(harness, path, Landing(harness, marker), deferred: false);

		probe.Value.ShouldBeTrue();
		ShouldBeBoundTo(await CookiePrincipalAsync(harness, probe, deferred: false), marker);
	}

	[Theory]
	[InlineData("", "/app/connect/authorize")]
	[InlineData("/app", "/connect/authorize")]
	[InlineData("/app", "/other/connect/authorize")]
	async Task A_landing_outside_the_path_base_stamps_nothing(string pathBase, string authorizePath)
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var landing = $"{authorizePath}?client_id=norse&norse_reauth="
			+ Markers(harness).Protect(Mint(harness, harness.User.Id));

		await ShouldStampNothingAsync(harness, "password", landing, new(pathBase));
	}

	[Fact]
	async Task A_landing_under_the_path_base_stamps_the_marker()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var marker = Mint(harness, harness.User.Id);

		var probe = await SignInAsync(harness, "password", "/app" + Landing(harness, marker), deferred: false,
			pathBase: new("/app"));

		ShouldBeBoundTo(await CookiePrincipalAsync(harness, probe, deferred: false), marker);
	}

	// T4-1: the stamp point reads the slot alone. A landing left parked for a sign-in that is neither of the two fill
	// sites (registration's own sign-in, any direct SignInWithClaimsAsync) binds nothing.
	[Fact]
	async Task The_stamp_point_reads_only_the_landing_slot()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		var landing = Landing(harness, Mint(harness, harness.User.Id));

		var probe = await harness.RunAsync(async manager =>
		{
			using (ParkedReturnUrl.Park(manager.Context, landing))
				await manager.SignInAsync(harness.User, isPersistent: false);
		});

		probe.Exception.ShouldBeNull();
		ShouldBeUnbound(await CookiePrincipalAsync(harness, probe, deferred: false));
	}

	static async Task ShouldStampNothingAsync(TwoFactorHarness harness, string path, string landing,
		PathString pathBase = default)
	{
		var probe = await SignInAsync(harness, path, landing, deferred: false, pathBase: pathBase);

		probe.Exception.ShouldBeNull();
		probe.Value.ShouldBeTrue("the sign-in itself succeeds");
		ShouldBeUnbound(await CookiePrincipalAsync(harness, probe, deferred: false));
	}

	static void ShouldBeBoundTo(ClaimsPrincipal principal, ReauthMarker marker) =>
		Guid.Parse(principal.FindAll(NorseSignInManager.ReauthClaimType).ShouldHaveSingleItem().Value)
			.ShouldBe(marker.MarkerId);

	static void ShouldBeUnbound(ClaimsPrincipal principal)
	{
		principal.HasClaim(static claim => claim.Type == NorseSignInManager.ReauthClaimType).ShouldBeFalse();
		principal.HasClaim(static claim => claim.Type == NorseClaimTypes.AuthTime).ShouldBeTrue("still a credential sign-in");
	}

	static ReauthMarkers Markers(TwoFactorHarness harness) =>
		new(harness.Services.GetRequiredService<IDataProtectionProvider>(), harness.Clock);

	static ReauthMarker Mint(TwoFactorHarness harness, Guid? userId) =>
		new(Guid.NewGuid(), userId, new byte[32], harness.Clock.GetUtcNow() + ReauthMarkers.Lifetime);

	// The authorize request a challenge returns to, its marker included.
	static string Landing(TwoFactorHarness harness, ReauthMarker marker) =>
		"/connect/authorize?client_id=norse&response_type=code&state=s&norse_reauth=" + Markers(harness).Protect(marker);

	// One credential path, with the landing parked the way its handler parks it. The challenge paths mint on a real
	// request first; the completion carries the landing in the token. after runs on the completing request, past the
	// sign-in, thrown or not.
	static async Task<TwoFactorHarness.Probe<bool>> SignInAsync(TwoFactorHarness harness, string path, string landing,
		bool deferred, Action<NorseSignInManager>? after = null, PathString pathBase = default)
	{
		Func<NorseSignInManager, Task<bool>> complete;
		switch (path)
		{
			case "password":
				harness.UserManager.GetTwoFactorEnabledAsync(harness.User).Returns(false);
				complete = async manager =>
				{
					using (ParkedReturnUrl.Park(manager.Context, landing))
						return (await manager.PasswordSignInAsync(harness.User, TwoFactorHarness.Password,
							isPersistent: false, lockoutOnFailure: false)).Succeeded;
				};
				break;
			case "passkey":
				var state = await PasskeyStateAsync(harness);
				complete = async manager =>
				{
					using (ParkedReturnUrl.Park(manager.Context, landing))
						return (await manager.PasskeyAssertionSignInAsync(CredentialJson, state, isPersistent: false,
							Cancellation)).Succeeded;
				};
				break;
			default:
				var token = await MintChallengeAsync(harness, path, landing, pathBase);
				complete = async manager => (await Complete(manager, path, token)).Result.Succeeded;
				break;
		}

		return await harness.RunAsync(async manager =>
		{
			if (pathBase.HasValue)
				manager.Context.Request.PathBase = pathBase;
			try
			{
				return await complete(manager);
			}
			finally
			{
				after?.Invoke(manager);
			}
		}, deferred);
	}

	static async Task<string> MintChallengeAsync(TwoFactorHarness harness, string path, string landing,
		PathString pathBase = default)
	{
		var minted = await harness.RunAsync(async manager =>
		{
			if (pathBase.HasValue)
				manager.Context.Request.PathBase = pathBase;
			using (ParkedReturnUrl.Park(manager.Context, landing))
				return path == "external login" ?
					await manager.ExternalLoginSignInAsync(TwoFactorHarness.ExternalProvider,
						TwoFactorHarness.ExternalProviderKey, isPersistent: false, bypassTwoFactor: false) :
					await manager.PasswordSignInAsync(harness.User, TwoFactorHarness.Password, isPersistent: false,
						lockoutOnFailure: false);
		});
		minted.Value.ShouldNotBeNull().RequiresTwoFactor.ShouldBeTrue();
		return minted.Token.ShouldNotBeNull();
	}

	static Task<ChallengeSignInResult> Complete(NorseSignInManager manager, string path, string token) =>
		path == "recovery code" ?
			manager.RecoveryCodeChallengeSignInAsync(token, TwoFactorHarness.RecoveryCode) :
			manager.TwoFactorChallengeSignInAsync(token, TwoFactorHarness.AuthenticatorCode, rememberClient: false);

	static async Task<string> PasskeyStateAsync(TwoFactorHarness harness)
	{
		harness.PasskeyHandler.MakeRequestOptionsAsync(Arg.Any<NorseUser?>(), Arg.Any<HttpContext>())
			.Returns(new PasskeyRequestOptionsResult
			{
				RequestOptionsJson = "{\"challenge\":\"request\"}",
				AssertionState = RawAssertionState
			});
		harness.PasskeyHandler.PerformAssertionAsync(Arg.Any<PasskeyAssertionContext>())
			.Returns(PasskeyAssertionResult.Success(TestPasskeys.Info([0x0A]), harness.User));
		return (await harness.RunAsync(manager => manager.CreatePasskeyRequestOptionsAsync(Cancellation)))
			.Value.ShouldNotBeNull().State;
	}

	// The identity cookie the browser holds after the sign-in: written by the request itself or, deferred, by the
	// /_auth/complete hop the stash key names.
	static async Task<ClaimsPrincipal> CookiePrincipalAsync(TwoFactorHarness harness, TwoFactorHarness.Probe<bool> probe,
		bool deferred)
	{
		if (!deferred)
			return harness.Decrypt(_scheme, probe.SetCookieFor(ApplicationCookie).ShouldNotBeNull()).Principal;

		probe.SetCookieFor(ApplicationCookie).ShouldBeNull("a circuit cannot write the cookie");
		var completion = harness.DeferredSignIn.BuildCompletionUrl(probe.IdentityKey.ShouldNotBeNull(), "/");
		var setCookies = await harness.GetSetCookiesAsync(completion);
		var setCookie = setCookies.Single(static header =>
			header.StartsWith($"{ApplicationCookie}=", StringComparison.Ordinal));
		return harness.Decrypt(_scheme, setCookie).Principal;
	}
}
