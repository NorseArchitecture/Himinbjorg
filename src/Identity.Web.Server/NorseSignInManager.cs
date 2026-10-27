using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;

namespace Norse.Identity.Web.Server;

/// <summary>
///     Overrides <see cref="SignInWithClaimsAsync(NorseUser, bool, IEnumerable{Claim})" />,
///     <see cref="SignInWithClaimsAsync(NorseUser, AuthenticationProperties?, IEnumerable{Claim})" />,
///     <see cref="SignOutAsync" />, <see cref="SignInOrTwoFactorAsync" /> (a token, never a cookie),
///     <see cref="RememberTwoFactorClientAsync" />, <see cref="ForgetTwoFactorClientAsync" />, and the read side,
///     <see cref="IsTwoFactorClientRememberedAsync" /> -- every seam ASP.NET Core Identity's
///     sign-in/sign-out/two-factor paths are actually known to route a raw cookie write (or a first cookie
///     authenticate) through, confirmed one at a time by decompiling the real installed assembly (ilspycmd over
///     <c>Microsoft.AspNetCore.Identity</c> 11.0.0-rc.3, 2026-10-26) rather than assumed -- to detect when the
///     caller is an already-established Blazor Server interactive circuit (<c>Context.Response.HasStarted</c>):
///     cookie writes are impossible there, not merely inconvenient, and so is the first authenticate of a cookie
///     scheme (<c>CookieAuthenticationHandler.InitializeHandlerAsync</c> registers <c>Response.OnStarting</c>,
///     which throws once the response has started -- on Kestrel and TestServer alike). When detected, defers via
///     <see cref="IDeferredSignIn" /> instead of writing the cookie directly and stashes the completion key on
///     <c>HttpContext.Items</c> (<see cref="DeferredSignInKeyItemName" /> for the identity cookie,
///     <see cref="DeferredRememberClientKeyItemName" /> for the remember-machine cookie) for the caller to read
///     back. Every other call path (WASM/MAUI over gRPC-Web, any static-SSR request) is a real, distinct HTTP
///     request with <c>Response.HasStarted == false</c> and behaves exactly as the unmodified base class would.
///     <see cref="SignInManager{TUser}.RefreshSignInAsync" /> needs no override of its own: the decompile shows it funnels through
///     <see cref="SignInWithClaimsAsync(NorseUser, AuthenticationProperties?, IEnumerable{Claim})" />.
///     This list has grown by exactly this kind of gap before -- <see cref="SignInOrTwoFactorAsync" /> shipped
///     uncovered at first -- so treat "every seam" as a standing claim to re-verify, not a settled fact, the
///     next time a new ASP.NET Core Identity entry point is wired here.
///     <para>
///         The two-factor challenge is a <see cref="TwoFactorChallenge" /> token parked on
///         <see cref="TwoFactorChallengeItemName" />, never the framework's partial two-factor-user-id cookie:
///         the base class's two-factor completion methods read that cookie (or private state only its own
///         <c>SignInOrTwoFactorAsync</c> sets), so this platform completes the second factor through
///         <see cref="TwoFactorChallengeSignInAsync" /> and <see cref="RecoveryCodeChallengeSignInAsync" />
///         instead, which reproduce the base's private completion over the token.
///     </para>
///     <para>
///         Known gap: the base's completion also signs out <c>IdentityConstants.ExternalScheme</c>. That sign-out
///         is performed here only while the response can still write a cookie and skipped on a circuit, where an
///         external cookie left behind expires on its own (five minutes). External login bypasses two-factor
///         today, so the branch is unreachable until Train 3 revisits it. Likewise, a remember-machine cookie
///         <see cref="IsTwoFactorClientRememberedAsync" /> rejects on a circuit (expired, another user, or a stamp
///         rotated past the validation interval) is left behind there rather than expired by the handler, and
///         expires on its own; on a real request the handler's own validator expires it as usual.
///     </para>
///     Lives in <c>Identity.Web.Server</c>, not the base <c>Identity</c> project -- <c>Identity</c> is shared
///     with <c>Identity.Migrations</c> (a console tool), and everything this type touches
///     (<see cref="HttpContext" />, <see cref="AuthenticationProperties" />, <see cref="IDeferredSignIn" />) is an
///     ASP.NET-Core-web-hosting concern migration tooling has no business depending on.
/// </summary>
public sealed class NorseSignInManager(
	UserManager<NorseUser> userManager,
	IHttpContextAccessor contextAccessor,
	IUserClaimsPrincipalFactory<NorseUser> claimsFactory,
	IOptions<IdentityOptions> optionsAccessor,
	ILogger<SignInManager<NorseUser>> logger,
	IAuthenticationSchemeProvider schemes,
	IUserConfirmation<NorseUser> confirmation,
	IDeferredSignIn deferredSignIn,
	IDataProtectionProvider dataProtectionProvider)
	: SignInManager<NorseUser>(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes,
		confirmation)
{
	/// <summary>The <c>HttpContext.Items</c> key under which a deferred completion key is stashed, when one is needed.</summary>
	public const string DeferredSignInKeyItemName = "Norse.DeferredSignInKey";

	/// <summary>
	///     The <c>HttpContext.Items</c> key under which a deferred remember-machine (two-factor client) cookie
	///     stash key is parked, when one is needed -- set by <see cref="RememberTwoFactorClientAsync" /> and
	///     <see cref="ForgetTwoFactorClientAsync" /> on an established circuit.
	/// </summary>
	public const string DeferredRememberClientKeyItemName = "Norse.DeferredRememberClientKey";

	/// <summary>
	///     The <c>HttpContext.Items</c> key under which the minted <see cref="TwoFactorChallenge" /> token is
	///     parked when a sign-in answers <see cref="SignInResult.TwoFactorRequired" />, for <c>LoginHandler</c>
	///     to carry back to the client.
	/// </summary>
	public const string TwoFactorChallengeItemName = "Norse.TwoFactorChallenge";

	readonly ITimeLimitedDataProtector _challengeProtector =
		dataProtectionProvider.CreateProtector(TwoFactorChallenge.Purpose).ToTimeLimitedDataProtector();

	// Both overloads override explicitly, independently -- do NOT assume one delegates to the other
	// inside the base class and skip overriding it. Getting this wrong silently reintroduces the crash
	// on whichever overload isn't actually hooked. Verify this claim yourself if you have any doubt
	// (e.g. decompile the real installed assembly), don't take this comment on faith either.
	/// <summary>Forwards to the <see cref="AuthenticationProperties" /> overload, which carries the actual deferral logic.</summary>
	public override async Task SignInWithClaimsAsync(NorseUser user, bool isPersistent,
		IEnumerable<Claim> additionalClaims) =>
		await SignInWithClaimsAsync(user, new AuthenticationProperties { IsPersistent = isPersistent },
			additionalClaims).ConfigureAwait(false);

	/// <summary>
	///     Signs in normally when the response can still write a cookie; otherwise stashes the sign-in via
	///     <see cref="IDeferredSignIn" /> and records the completion key on <see cref="DeferredSignInKeyItemName" />.
	/// </summary>
	public override async Task SignInWithClaimsAsync(NorseUser user, AuthenticationProperties? authenticationProperties,
		IEnumerable<Claim> additionalClaims)
	{
		if (!Context.Response.HasStarted)
		{
			await base.SignInWithClaimsAsync(user, authenticationProperties, additionalClaims).ConfigureAwait(false);
			return;
		}

		var principal = await CreateUserPrincipalAsync(user).ConfigureAwait(false);
		((ClaimsIdentity)principal.Identity!).AddClaims(additionalClaims);
		var key = deferredSignIn.StashSignIn(AuthenticationScheme, principal,
			authenticationProperties ?? new AuthenticationProperties());
		Context.Items[DeferredSignInKeyItemName] = key;
	}

	/// <summary>
	///     Signs out normally when the response can still write a cookie; otherwise stashes the sign-out via
	///     <see cref="IDeferredSignIn" /> and records the completion key on <see cref="DeferredSignInKeyItemName" />.
	/// </summary>
	public override async Task SignOutAsync()
	{
		if (!Context.Response.HasStarted)
		{
			await base.SignOutAsync().ConfigureAwait(false);
			return;
		}

		var key = deferredSignIn.StashSignOut(AuthenticationScheme);
		Context.Items[DeferredSignInKeyItemName] = key;
	}

	// The base class's own 2FA-required branch (decompiled RC3) stores the user in private state and writes
	// the partial two-factor cookie via a raw Context.SignInAsync(TwoFactorUserIdScheme, ...) call that funnels
	// through no overridable seam -- on an established circuit that throws before TwoFactorRequired is ever
	// returned. Neither the private state nor the cookie is reachable from here, so the challenge leaves as a
	// token instead and the base is never called on this branch, on any path.
	/// <summary>
	///     Delegates to the base class unless a second factor is genuinely required; then mints a
	///     <see cref="TwoFactorChallenge" /> bound to the user's current security stamp, parks its token on
	///     <see cref="TwoFactorChallengeItemName" />, and answers <see cref="SignInResult.TwoFactorRequired" />
	///     without writing any cookie.
	/// </summary>
	protected override async Task<SignInResult> SignInOrTwoFactorAsync(NorseUser user, bool isPersistent,
		string? loginProvider = null, bool bypassTwoFactor = false)
	{
		var requiresTwoFactor = !bypassTwoFactor
			&& await IsTwoFactorEnabledAsync(user).ConfigureAwait(false)
			&& !await IsTwoFactorClientRememberedAsync(user).ConfigureAwait(false);
		if (!requiresTwoFactor)
			return await base.SignInOrTwoFactorAsync(user, isPersistent, loginProvider, bypassTwoFactor)
				.ConfigureAwait(false);

		TwoFactorChallenge challenge = new(
			await UserManager.GetUserIdAsync(user).ConfigureAwait(false),
			await UserManager.GetSecurityStampAsync(user).ConfigureAwait(false),
			isPersistent,
			loginProvider);
		Context.Items[TwoFactorChallengeItemName] = challenge.Protect(_challengeProtector);
		return SignInResult.TwoFactorRequired;
	}

	/// <summary>
	///     Completes a challenge with an authenticator code: the reproduction of the base's
	///     <c>TwoFactorAuthenticatorSignInAsync</c> over the token. A token that is invalid, expired, for an
	///     unknown user, or minted before a stamp rotation answers <see cref="SignInResult.Failed" />; a wrong
	///     code counts toward lockout. A shredded subject's <see cref="KeyDestroyedException" /> propagates to
	///     the <c>.Outcome</c> view, which classifies it.
	/// </summary>
	/// <param name="token">The token <see cref="SignInOrTwoFactorAsync" /> parked.</param>
	/// <param name="code">The authenticator code; spaces and hyphens are stripped before verification.</param>
	/// <param name="rememberClient">Whether to remember this client so the second factor is not asked again.</param>
	/// <returns>The sign-in result.</returns>
	public async Task<SignInResult> TwoFactorChallengeSignInAsync(string token, string code, bool rememberClient)
	{
		if (await ResolveChallengeAsync(token).ConfigureAwait(false) is not (var user, var challenge))
			return SignInResult.Failed;
		if (await PreSignInCheck(user).ConfigureAwait(false) is { } refused)
			return refused;

		var normalized = code
			.Replace(" ", string.Empty, StringComparison.Ordinal)
			.Replace("-", string.Empty, StringComparison.Ordinal);
		if (await UserManager.VerifyTwoFactorTokenAsync(user, Options.Tokens.AuthenticatorTokenProvider, normalized)
				.ConfigureAwait(false))
			return await CompleteTwoFactorSignInAsync(user, challenge, challenge.IsPersistent, rememberClient)
				.ConfigureAwait(false);

		if (UserManager.SupportsUserLockout)
		{
			if (!(await UserManager.AccessFailedAsync(user).ConfigureAwait(false) ?? IdentityResult.Success).Succeeded)
				return SignInResult.Failed;
			if (await UserManager.IsLockedOutAsync(user).ConfigureAwait(false))
				return await LockedOut(user).ConfigureAwait(false);
		}

		return SignInResult.Failed;
	}

	/// <summary>
	///     Completes a challenge with a recovery code: the reproduction of the base's
	///     <c>TwoFactorRecoveryCodeSignInAsync</c> over the token, with the same prelude as
	///     <see cref="TwoFactorChallengeSignInAsync" />. The sign-in is never persistent and never remembers the
	///     client, and a wrong code does not count toward lockout (parity with the base).
	/// </summary>
	/// <param name="token">The token <see cref="SignInOrTwoFactorAsync" /> parked.</param>
	/// <param name="code">The recovery code; spaces are stripped before redemption.</param>
	/// <returns>The sign-in result.</returns>
	public async Task<SignInResult> RecoveryCodeChallengeSignInAsync(string token, string code)
	{
		if (await ResolveChallengeAsync(token).ConfigureAwait(false) is not (var user, var challenge))
			return SignInResult.Failed;
		if (await PreSignInCheck(user).ConfigureAwait(false) is { } refused)
			return refused;

		var normalized = code.Replace(" ", string.Empty, StringComparison.Ordinal);
		var redeemed = await UserManager.RedeemTwoFactorRecoveryCodeAsync(user, normalized).ConfigureAwait(false);
		return redeemed.Succeeded ?
			await CompleteTwoFactorSignInAsync(user, challenge, isPersistent: false, rememberClient: false)
				.ConfigureAwait(false) :
			SignInResult.Failed;
	}

	/// <summary>
	///     Remembers the client normally when the response can still write a cookie; otherwise stashes the
	///     remember-me cookie's sign-in via <see cref="IDeferredSignIn" /> and records the completion key on
	///     <see cref="DeferredRememberClientKeyItemName" />.
	/// </summary>
	public override async Task RememberTwoFactorClientAsync(NorseUser user)
	{
		if (!Context.Response.HasStarted)
		{
			await base.RememberTwoFactorClientAsync(user).ConfigureAwait(false);
			return;
		}

		var principal = await BuildRememberClientPrincipalAsync(user).ConfigureAwait(false);
		Context.Items[DeferredRememberClientKeyItemName] = deferredSignIn.StashSignIn(
			IdentityConstants.TwoFactorRememberMeScheme, principal, new AuthenticationProperties { IsPersistent = true });
	}

	/// <summary>
	///     Forgets the client normally when the response can still write a cookie; otherwise stashes the
	///     remember-me cookie's sign-out via <see cref="IDeferredSignIn" /> and records the completion key on
	///     <see cref="DeferredRememberClientKeyItemName" />.
	/// </summary>
	public override async Task ForgetTwoFactorClientAsync()
	{
		if (!Context.Response.HasStarted)
		{
			await base.ForgetTwoFactorClientAsync().ConfigureAwait(false);
			return;
		}

		Context.Items[DeferredRememberClientKeyItemName] =
			deferredSignIn.StashSignOut(IdentityConstants.TwoFactorRememberMeScheme);
	}

	// The base authenticates TwoFactorRememberMeScheme through the cookie handler, whose first use on a request
	// registers Response.OnStarting -- impossible once the response has started. On a circuit the cookie is read
	// without the handler instead: the same ticket format, the same three checks the handler and its
	// TwoFactorSecurityStampValidator make (decompiled RC3: expiry against the cookie options' clock, the name
	// claim against the user id, and the stamp claim only once the ticket is older than
	// SecurityStampValidatorOptions.ValidationInterval), and no write of any kind. The base's own password step
	// (CheckPasswordSignInCoreAsync) calls this virtual too, so it is the one seam covering both.
	/// <summary>
	///     Answers whether this client is remembered for the second factor: through the base (the cookie handler)
	///     when the response has not started, otherwise by reading the remember-machine cookie directly, with the
	///     handler's own checks reproduced. A missing, unreadable, expired, foreign, or stale-stamped cookie answers
	///     <see langword="false" />, never throws.
	/// </summary>
	public override async Task<bool> IsTwoFactorClientRememberedAsync(NorseUser user)
	{
		if (!Context.Response.HasStarted)
			return await base.IsTwoFactorClientRememberedAsync(user).ConfigureAwait(false);

		var services = Context.RequestServices;
		if (await services.GetRequiredService<IAuthenticationSchemeProvider>()
				.GetSchemeAsync(IdentityConstants.TwoFactorRememberMeScheme).ConfigureAwait(false) is null)
			return false;

		var options = services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
			.Get(IdentityConstants.TwoFactorRememberMeScheme);
		if (options.CookieManager.GetRequestCookie(Context, options.Cookie.Name!) is not { Length: > 0 } cookie)
			return false;

		AuthenticationTicket? ticket;
		try
		{
			ticket = options.TicketDataFormat.Unprotect(cookie);
		}
		catch (CryptographicException)
		{
			return false;
		}

		if (ticket is null)
			return false;
		var now = (options.TimeProvider ?? TimeProvider.System).GetUtcNow();
		if (ticket.Properties.ExpiresUtc is { } expiresUtc && expiresUtc < now)
			return false;
		if (ticket.Principal.FindFirstValue(ClaimTypes.Name)
			!= await UserManager.GetUserIdAsync(user).ConfigureAwait(false))
			return false;
		if (!UserManager.SupportsUserSecurityStamp)
			return true;

		var validator = services.GetRequiredService<IOptions<SecurityStampValidatorOptions>>().Value;
		var validatorNow = (validator.TimeProvider ?? TimeProvider.System).GetUtcNow();
		if (ticket.Properties.IssuedUtc is { } issuedUtc && validatorNow - issuedUtc <= validator.ValidationInterval)
			return true;
		return ticket.Principal.FindFirstValue(Options.ClaimsIdentity.SecurityStampClaimType)
			== await UserManager.GetSecurityStampAsync(user).ConfigureAwait(false);
	}

	/// <summary>
	///     Folds a destroyed key into a clean dead-session verdict. Law: a destroyed key IS a dead
	///     session -- erasure (<c>Norse.Identity.Web.Server.ErasureService</c>) destroys the subject's key
	///     before its transaction deletes the row, and in that window every attempt to re-materialize the row's
	///     protected columns (<c>Email</c>, <c>UserName</c>, both still wired through
	///     <see cref="NorsePersonalDataProtector" />'s EF value converter) throws
	///     <see cref="KeyDestroyedException" />, unwrapped, straight out of EF's materializer -- including
	///     from <c>UserManager.GetUserAsync</c>, which the base implementation calls to re-hydrate the
	///     principal's subject. Left uncaught, a shredded subject's surviving cookie 500-loops out of the
	///     cookie authentication middleware on every request instead of being rejected cleanly. This
	///     catch is deliberately narrow: it lives ONLY at this revalidation boundary. Every other path
	///     (<see cref="NorseUserStore" />, <see cref="NorsePersonalDataProtector" /> itself, and the challenge
	///     sign-ins above) must keep throwing -- the disclosure surface's <c>Erased</c> fold depends on the
	///     exception surviving there, and catching it earlier would silence that signal for good. The classification
	///     is <see cref="IdentityOutcomeMap.IsErased" />, the one the <c>Erased</c> mapping row and the revalidating
	///     state provider share (2026-10-24 explicit-writes spec §4.12).
	/// </summary>
	public override async Task<NorseUser?> ValidateSecurityStampAsync(ClaimsPrincipal? principal)
	{
		try
		{
			return await base.ValidateSecurityStampAsync(principal).ConfigureAwait(false);
		}
		catch (Exception exception) when (IdentityOutcomeMap.IsErased(exception))
		{
			return null;
		}
	}

	/// <summary>
	///     The shared prelude of both challenge sign-ins: the token unprotected, its user found, and the stamp
	///     it was minted under still current. Anything else answers <see langword="null" />.
	/// </summary>
	async Task<(NorseUser User, TwoFactorChallenge Challenge)?> ResolveChallengeAsync(string token)
	{
		if (!TwoFactorChallenge.TryUnprotect(_challengeProtector, token, out var challenge))
			return null;
		var user = await UserManager.FindByIdAsync(challenge.UserId).ConfigureAwait(false);
		if (user is null || await UserManager.GetSecurityStampAsync(user).ConfigureAwait(false) != challenge.SecurityStamp)
			return null;
		return (user, challenge);
	}

	// The reproduction of the base's private DoTwoFactorSignInAsync (decompiled RC3, 2026-10-26). The base gates
	// completion on a successful lockout reset -- its protected ResetLockout throws a framework-private
	// IdentityResultException that a private ResetLockoutWithResult catches, neither usable from here -- so
	// the reset is called directly: on this store it can answer IndeterminateOutcome with no exception, and a
	// sign-in must not be issued over it. The base also signs out TwoFactorUserIdScheme; that cookie is never
	// written on this platform, so that sign-out is dropped. The external-scheme sign-out is kept only while the
	// response can still write (see the class doc's known gap), and the registration check mirrors the base's
	// own, read from the request's services since the scheme provider handed to the base is not retained here.
	async Task<SignInResult> CompleteTwoFactorSignInAsync(NorseUser user, TwoFactorChallenge challenge,
		bool isPersistent, bool rememberClient)
	{
		if (UserManager.SupportsUserLockout
			&& !(await UserManager.ResetAccessFailedCountAsync(user).ConfigureAwait(false) ?? IdentityResult.Success)
				.Succeeded)
			return SignInResult.Failed;

		List<Claim> claims = [new("amr", "mfa")];
		if (challenge.LoginProvider is { } loginProvider)
			claims.Add(new(ClaimTypes.AuthenticationMethod, loginProvider));

		if (!Context.Response.HasStarted
			&& await Context.RequestServices.GetRequiredService<IAuthenticationSchemeProvider>()
				.GetSchemeAsync(IdentityConstants.ExternalScheme).ConfigureAwait(false) is not null)
			await Context.SignOutAsync(IdentityConstants.ExternalScheme).ConfigureAwait(false);
		if (rememberClient)
			await RememberTwoFactorClientAsync(user).ConfigureAwait(false);
		await SignInWithClaimsAsync(user, isPersistent, claims).ConfigureAwait(false);
		return SignInResult.Success;
	}

	// The complete principal the base's internal StoreRememberClient builds (decompiled RC3): the name claim
	// IsTwoFactorClientRememberedAsync compares, and the security-stamp claim TwoFactorSecurityStampValidator
	// reads once the cookie is older than SecurityStampValidatorOptions.ValidationInterval -- a principal
	// without it is a cookie the validator rejects on its first run. The direct path still delegates to the
	// base; NorseSignInManagerTests holds the two shapes together.
	async Task<ClaimsPrincipal> BuildRememberClientPrincipalAsync(NorseUser user)
	{
		ClaimsIdentity identity = new(IdentityConstants.TwoFactorRememberMeScheme);
		identity.AddClaim(new Claim(ClaimTypes.Name, await UserManager.GetUserIdAsync(user).ConfigureAwait(false)));
		if (UserManager.SupportsUserSecurityStamp)
			identity.AddClaim(new Claim(Options.ClaimsIdentity.SecurityStampClaimType,
				await UserManager.GetSecurityStampAsync(user).ConfigureAwait(false)));
		return new ClaimsPrincipal(identity);
	}
}
