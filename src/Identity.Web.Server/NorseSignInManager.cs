using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Extensions;
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
///         External login requires the second factor (<see cref="ExternalLoginSignInAsync(string, string, bool, bool)" />
///         refuses a bypass), and the external-login callback clears <c>IdentityConstants.ExternalScheme</c> before it
///         redirects to the challenge. The base's completion also signs out that scheme; here that sign-out runs only
///         while the response can still write a cookie and is skipped on a circuit, a backstop where an external
///         cookie left behind expires on its own (five minutes). Likewise, a remember-machine cookie
///         <see cref="IsTwoFactorClientRememberedAsync" /> rejects on a circuit (expired, another user, or a stamp
///         rotated past the validation interval) is left behind there rather than expired by the handler, and
///         expires on its own; on a real request the handler's own validator expires it as usual.
///     </para>
///     <para>
///         Passkey registration runs through <see cref="CreatePasskeyOptionsAsync" /> and <see cref="AttestPasskeyAsync" />,
///         never the base's same-purpose members: those park the ceremony state in the partial two-factor cookie, so
///         here the state rides the ceremony itself, data-protected under <see cref="PasskeyAttestationPurpose" />.
///         The IL scan bans the five base passkey members by name (T3-15). Passkey sign-in runs the same way, through
///         <see cref="CreatePasskeyRequestOptionsAsync" /> and <see cref="PasskeyAssertionSignInAsync" />, under
///         <see cref="PasskeyAssertionPurpose" />, and each assertion state is burned in the one-shot ledger before the
///         handler sees it (T3-32).
///     </para>
///     Lives in <c>Identity.Web.Server</c>, not the base <c>Identity</c> project -- <c>Identity</c> is shared
///     with <c>Identity.Migrations</c> (a console tool), and everything this type touches
///     (<see cref="HttpContext" />, <see cref="AuthenticationProperties" />, <see cref="IDeferredSignIn" />) is an
///     ASP.NET-Core-web-hosting concern migration tooling has no business depending on.
/// </summary>
public sealed partial class NorseSignInManager(
	UserManager<NorseUser> userManager,
	IHttpContextAccessor contextAccessor,
	IUserClaimsPrincipalFactory<NorseUser> claimsFactory,
	IOptions<IdentityOptions> optionsAccessor,
	ILogger<SignInManager<NorseUser>> logger,
	IAuthenticationSchemeProvider schemes,
	IUserConfirmation<NorseUser> confirmation,
	IDeferredSignIn deferredSignIn,
	IDataProtectionProvider dataProtectionProvider,
	IPasskeyHandler<NorseUser> passkeyHandler,
	IOptions<IdentityPasskeyOptions> passkeyOptions,
	IPasskeyChallengeLedger passkeyChallengeLedger)
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

	/// <summary>
	///     The <c>HttpContext.Items</c> key under which a sign-in parks its resolved landing (through
	///     <see cref="ParkedReturnUrl" />) for <see cref="SignInOrTwoFactorAsync" /> to take into the
	///     <see cref="TwoFactorChallenge" /> it mints; without it, the challenge lands on the app root.
	/// </summary>
	internal const string ReturnUrlItemName = "Norse.Identity.ReturnUrl";

	/// <summary>
	///     The data-protection purpose of a passkey registration's ceremony state; a state protected under any other
	///     purpose -- a sign-in's included -- fails attestation.
	/// </summary>
	internal const string PasskeyAttestationPurpose = "Norse.Identity.PasskeyAttestation.v1";

	/// <summary>
	///     The data-protection purpose of a passkey sign-in's ceremony state; a state protected under any other purpose --
	///     a registration's included -- fails the assertion.
	/// </summary>
	internal const string PasskeyAssertionPurpose = "Norse.Identity.PasskeyAssertion.v1";

	/// <summary>
	///     What every failed attestation answers, whatever the cause: the handler's own message can name an origin or a
	///     credential, and is logged instead.
	/// </summary>
	internal const string AttestationFailedMessage = "The passkey could not be verified. Try again.";

	readonly ITimeLimitedDataProtector _challengeProtector =
		dataProtectionProvider.CreateProtector(TwoFactorChallenge.Purpose).ToTimeLimitedDataProtector();

	readonly ITimeLimitedDataProtector _attestationProtector =
		dataProtectionProvider.CreateProtector(PasskeyAttestationPurpose).ToTimeLimitedDataProtector();

	readonly ITimeLimitedDataProtector _assertionProtector =
		dataProtectionProvider.CreateProtector(PasskeyAssertionPurpose).ToTimeLimitedDataProtector();

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

	// T3-18 (Buvy): the platform's second factor never depends on the provider's. The base three-argument overload
	// (decompiled RC3, 2026-10-28) forwards here with bypassTwoFactor: false, so it stays legal.
	/// <summary>
	///     Signs in with an external login, always through the second factor: a caller asking to bypass it is a
	///     programming error, refused before any lookup.
	/// </summary>
	/// <exception cref="InvalidOperationException"><paramref name="bypassTwoFactor" /> is <see langword="true" />.</exception>
	public override Task<SignInResult> ExternalLoginSignInAsync(string loginProvider, string providerKey,
		bool isPersistent, bool bypassTwoFactor) =>
		bypassTwoFactor ?
			throw new InvalidOperationException("External login requires the second factor; it is never bypassed.") :
			base.ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent, bypassTwoFactor);

	// The base class's own 2FA-required branch (decompiled RC3) stores the user in private state and writes
	// the partial two-factor cookie via a raw Context.SignInAsync(TwoFactorUserIdScheme, ...) call that funnels
	// through no overridable seam -- on an established circuit that throws before TwoFactorRequired is ever
	// returned. Neither the private state nor the cookie is reachable from here, so the challenge leaves as a
	// token instead and the base is never called on this branch, on any path.
	/// <summary>
	///     Delegates to the base class unless a second factor is genuinely required; then mints a
	///     <see cref="TwoFactorChallenge" /> bound to the user's current security stamp and carrying the landing parked
	///     on <see cref="ReturnUrlItemName" /> (taken and removed; the app root when none is parked), parks its token on
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

		var returnUrl = Context.Items[ReturnUrlItemName] as string
			?? UriHelper.BuildRelative(Context.Request.PathBase, "/");
		Context.Items.Remove(ReturnUrlItemName);
		TwoFactorChallenge challenge = new(
			await UserManager.GetUserIdAsync(user).ConfigureAwait(false),
			await UserManager.GetSecurityStampAsync(user).ConfigureAwait(false),
			isPersistent,
			loginProvider,
			returnUrl);
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
	/// <returns>The sign-in result, carrying the challenge's landing on success.</returns>
	public async Task<ChallengeSignInResult> TwoFactorChallengeSignInAsync(string token, string code,
		bool rememberClient)
	{
		if (await ResolveChallengeAsync(token).ConfigureAwait(false) is not (var user, var challenge))
			return Refused(SignInResult.Failed);
		if (await PreSignInCheck(user).ConfigureAwait(false) is { } refused)
			return Refused(refused);

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
				return Refused(SignInResult.Failed);
			if (await UserManager.IsLockedOutAsync(user).ConfigureAwait(false))
				return Refused(await LockedOut(user).ConfigureAwait(false));
		}

		return Refused(SignInResult.Failed);
	}

	/// <summary>
	///     Completes a challenge with a recovery code: the reproduction of the base's
	///     <c>TwoFactorRecoveryCodeSignInAsync</c> over the token, with the same prelude as
	///     <see cref="TwoFactorChallengeSignInAsync" />. The sign-in is never persistent and never remembers the
	///     client, and a wrong code does not count toward lockout (parity with the base).
	/// </summary>
	/// <param name="token">The token <see cref="SignInOrTwoFactorAsync" /> parked.</param>
	/// <param name="code">The recovery code; spaces are stripped before redemption.</param>
	/// <returns>The sign-in result, carrying the challenge's landing on success.</returns>
	public async Task<ChallengeSignInResult> RecoveryCodeChallengeSignInAsync(string token, string code)
	{
		if (await ResolveChallengeAsync(token).ConfigureAwait(false) is not (var user, var challenge))
			return Refused(SignInResult.Failed);
		if (await PreSignInCheck(user).ConfigureAwait(false) is { } refused)
			return Refused(refused);

		var normalized = code.Replace(" ", string.Empty, StringComparison.Ordinal);
		var redeemed = await UserManager.RedeemTwoFactorRecoveryCodeAsync(user, normalized).ConfigureAwait(false);
		return redeemed.Succeeded ?
			await CompleteTwoFactorSignInAsync(user, challenge, isPersistent: false, rememberClient: false)
				.ConfigureAwait(false) :
			Refused(SignInResult.Failed);
	}

	// The base's MakePasskeyCreationOptionsAsync/PerformPasskeyAttestationAsync (decompiled RC3, 2026-10-28) park the
	// handler's attestation state in the partial two-factor cookie (TwoFactorUserIdScheme) -- a cookie write a circuit
	// cannot make, and the cookie is never written on this platform. The state rides the ceremony instead, protected
	// under its own purpose for the handler's AuthenticatorTimeout, and the handler itself is called directly.
	/// <summary>
	///     Begins a passkey registration for <paramref name="user" />: the handler's creation options, and its
	///     attestation state protected under <see cref="PasskeyAttestationPurpose" /> for
	///     <see cref="IdentityPasskeyOptions.AuthenticatorTimeout" />. The state binds the user entity the options name,
	///     which the caller checks against the account completing the ceremony.
	/// </summary>
	/// <param name="user">The user registering a passkey.</param>
	/// <param name="cancellationToken">Checked before the ceremony starts; the handler takes none.</param>
	/// <returns>The options and the protected state.</returns>
	public async Task<PasskeyCeremony> CreatePasskeyOptionsAsync(NorseUser user,
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		var userId = await UserManager.GetUserIdAsync(user).ConfigureAwait(false);
		var userName = await UserManager.GetUserNameAsync(user).ConfigureAwait(false) ?? "User";
		var options = await passkeyHandler.MakeCreationOptionsAsync(new()
		{
			Id = userId,
			Name = userName,
			DisplayName = userName
		}, Context).ConfigureAwait(false);
		var state = options.AttestationState
			?? throw new InvalidOperationException("The passkey handler answered no attestation state.");
		return new(options.CreationOptionsJson,
			_attestationProtector.Protect(state, passkeyOptions.Value.AuthenticatorTimeout));
	}

	/// <summary>
	///     Completes a passkey registration: the state <see cref="CreatePasskeyOptionsAsync" /> protected is unprotected
	///     before the handler sees it, and a state that is malformed, tampered with, expired or protected under another
	///     purpose fails with <see cref="AttestationFailedMessage" /> without reaching the handler. Nothing is saved here.
	/// </summary>
	/// <param name="credentialJson">The browser's attestation credential, as JSON.</param>
	/// <param name="attestationState">The protected state from <see cref="PasskeyCeremony.State" />.</param>
	/// <param name="cancellationToken">Checked before the attestation; the handler takes none.</param>
	/// <returns>The handler's attestation result, or the refusal.</returns>
	public async Task<PasskeyAttestationResult> AttestPasskeyAsync(string credentialJson, string attestationState,
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		string state;
		try
		{
			state = _attestationProtector.Unprotect(attestationState, out _);
		}
		// FormatException: the base64url decode that precedes the protector refuses a malformed state.
		catch (Exception exception) when (exception is CryptographicException or FormatException)
		{
			return PasskeyAttestationResult.Fail(new PasskeyException(AttestationFailedMessage));
		}

		var result = await passkeyHandler.PerformAttestationAsync(new()
		{
			HttpContext = Context,
			CredentialJson = credentialJson,
			AttestationState = state
		}).ConfigureAwait(false);
		if (!result.Succeeded)
			LogAttestationFailed(Logger, result.Failure.Message, result.Failure);
		return result;
	}

	/// <summary>
	///     Begins a passkey sign-in for no particular user (a discoverable credential): the handler's request options,
	///     and its assertion state protected under <see cref="PasskeyAssertionPurpose" /> for
	///     <see cref="IdentityPasskeyOptions.AuthenticatorTimeout" />. Nothing is stored, and nothing is consumed.
	/// </summary>
	/// <param name="cancellationToken">Checked before the ceremony starts; the handler takes none.</param>
	/// <returns>The options and the protected state.</returns>
	public async Task<PasskeyCeremony> CreatePasskeyRequestOptionsAsync(CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		var options = await passkeyHandler.MakeRequestOptionsAsync(user: null, Context).ConfigureAwait(false);
		var state = options.AssertionState
			?? throw new InvalidOperationException("The passkey handler answered no assertion state.");
		return new(options.RequestOptionsJson,
			_assertionProtector.Protect(state, passkeyOptions.Value.AuthenticatorTimeout));
	}

	// The reproduction of the base's PasskeySignInAsync (decompiled RC3, task 4.6 F6) over the protected state instead of
	// the partial two-factor cookie: the assertion, PreSignInCheck, AddOrUpdatePasskeyAsync (the sign-count update the
	// handler prepared), then SignInOrTwoFactorAsync with the recorded bypassTwoFactor: true -- a user-verified passkey
	// (UV is enforced in the handler, T3-33) is itself a multi-factor credential. As in the base, no lockout reset and no
	// lockout count. Two decisions are this platform's own: the state is consumed in the ledger after it unprotects and
	// before the handler runs, so a replay never reaches the handler or the sign-count write and a failed first
	// assertion still burns its challenge; and the caller's isPersistent is honored where the base hard-codes false.
	/// <summary>
	///     Completes a passkey sign-in. A state that is malformed, tampered with, expired, protected under another
	///     purpose or already consumed answers <see cref="SignInResult.Failed" /> without reaching the handler; so do a
	///     failed assertion and a failed sign-count update. A locked-out or not-allowed user answers the pre-sign-in
	///     check's refusal. A landing parked on <see cref="ReturnUrlItemName" /> is left for the challenge mint, which
	///     the recorded bypass never reaches.
	/// </summary>
	/// <param name="credentialJson">The browser's assertion credential, as JSON.</param>
	/// <param name="assertionState">The protected state from <see cref="PasskeyCeremony.State" />.</param>
	/// <param name="isPersistent">Whether the sign-in cookie persists.</param>
	/// <param name="cancellationToken">Cancels the ledger consumption; the handler takes none.</param>
	/// <returns>The sign-in result.</returns>
	public async Task<SignInResult> PasskeyAssertionSignInAsync(string credentialJson, string assertionState,
		bool isPersistent, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		string state;
		DateTimeOffset expiresAt;
		try
		{
			state = _assertionProtector.Unprotect(assertionState, out expiresAt);
		}
		// FormatException: the base64url decode that precedes the protector refuses a malformed state.
		catch (Exception exception) when (exception is CryptographicException or FormatException)
		{
			return SignInResult.Failed;
		}

		// The state's unprotected UTF-8 bytes carry the ceremony's random challenge and are byte-identical on every
		// replay of the same token (task 4.6 F8); the ledger hashes them itself (P5).
		if (!await passkeyChallengeLedger
				.TryConsumeAsync(Encoding.UTF8.GetBytes(state), expiresAt, cancellationToken)
				.ConfigureAwait(false))
			return SignInResult.Failed;

		var assertion = await passkeyHandler.PerformAssertionAsync(new()
		{
			HttpContext = Context,
			CredentialJson = credentialJson,
			AssertionState = state
		}).ConfigureAwait(false);
		if (!assertion.Succeeded)
		{
			LogAssertionFailed(Logger, assertion.Failure.Message, assertion.Failure);
			return SignInResult.Failed;
		}

		if (await PreSignInCheck(assertion.User).ConfigureAwait(false) is { } refused)
			return refused;
		if (!(await UserManager.AddOrUpdatePasskeyAsync(assertion.User, assertion.Passkey).ConfigureAwait(false))
				.Succeeded)
			return SignInResult.Failed;

		return await SignInOrTwoFactorAsync(assertion.User, isPersistent, loginProvider: null, bypassTwoFactor: true)
			.ConfigureAwait(false);
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
	// response can still write (a backstop: see the class doc), and the registration check mirrors the base's
	// own, read from the request's services since the scheme provider handed to the base is not retained here.
	async Task<ChallengeSignInResult> CompleteTwoFactorSignInAsync(NorseUser user, TwoFactorChallenge challenge,
		bool isPersistent, bool rememberClient)
	{
		if (UserManager.SupportsUserLockout
			&& !(await UserManager.ResetAccessFailedCountAsync(user).ConfigureAwait(false) ?? IdentityResult.Success)
				.Succeeded)
			return Refused(SignInResult.Failed);

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
		return new(SignInResult.Success, challenge.ReturnUrl);
	}

	// Only a completed sign-in carries the challenge's landing.
	static ChallengeSignInResult Refused(SignInResult result) =>
		new(result, string.Empty);

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

	// Information, with the exception: the handler folds a store fault into a failed ceremony, so the cause (an inner
	// exception) is logged here and never reaches the wire, whose answer stays the fixed refusal.
	[LoggerMessage(Level = LogLevel.Information, Message = "Passkey attestation failed: {Reason}")]
	static partial void LogAttestationFailed(ILogger logger, string reason, Exception exception);

	[LoggerMessage(Level = LogLevel.Information, Message = "Passkey assertion failed: {Reason}")]
	static partial void LogAssertionFailed(ILogger logger, string reason, Exception exception);
}
