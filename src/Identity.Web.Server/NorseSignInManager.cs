using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server;

/// <summary>
/// Overrides every seam ASP.NET Core Identity's sign-in/sign-out paths funnel through to detect when the
/// caller is an already-established Blazor Server interactive circuit (<c>Context.Response.HasStarted</c>)
/// — cookie writes are impossible there, not merely inconvenient. When detected, defers via
/// <see cref="IDeferredSignIn"/> instead of writing the cookie directly and stashes the completion key on
/// <c>HttpContext.Items</c> for the caller to read back. Every other call path (WASM/MAUI over gRPC-Web,
/// any static-SSR request) is a real, distinct HTTP request with <c>Response.HasStarted == false</c> and
/// behaves exactly as the unmodified base class would — zero behavior change for those paths.
///
/// Lives in <c>Identity.Web.Server</c>, not the base <c>Identity</c> project — <c>Identity</c> is shared
/// with <c>Identity.Migrations</c> (a console tool), and everything this type touches
/// (<see cref="HttpContext"/>, <see cref="AuthenticationProperties"/>, <see cref="IDeferredSignIn"/>) is an
/// ASP.NET-Core-web-hosting concern migration tooling has no business depending on.
/// </summary>
// CS9107 disabled deliberately, narrowly, right here: `schemes` has to be both forwarded to the base
// constructor (it wants its own copy, kept in a private field this class can't reach) AND retained by
// SignInOrTwoFactorAsync below, which needs its own IAuthenticationSchemeProvider.GetSchemeAsync check
// -- the exact one the base class's own 2FA branch makes, unreachable across the inheritance boundary.
// Safe: IAuthenticationSchemeProvider is a read-only query object with no disposal/ownership semantics,
// so two references to the same instance carry no risk the warning is generally guarding against.
#pragma warning disable CS9107
public sealed class NorseSignInManager(
	UserManager<NorseUser> userManager, IHttpContextAccessor contextAccessor,
	IUserClaimsPrincipalFactory<NorseUser> claimsFactory, IOptions<IdentityOptions> optionsAccessor,
	ILogger<SignInManager<NorseUser>> logger, IAuthenticationSchemeProvider schemes,
	IUserConfirmation<NorseUser> confirmation, IDeferredSignIn deferredSignIn)
	: SignInManager<NorseUser>(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
#pragma warning restore CS9107
{
	/// <summary>The <c>HttpContext.Items</c> key under which a deferred completion key is stashed, when one is needed.</summary>
	public const string DeferredSignInKeyItemName = "Norse.DeferredSignInKey";

	// Both overloads override explicitly, independently -- do NOT assume one delegates to the other
	// inside the base class and skip overriding it. Getting this wrong silently reintroduces the crash
	// on whichever overload isn't actually hooked. Verify this claim yourself if you have any doubt
	// (e.g. decompile the real installed assembly), don't take this comment on faith either.
	/// <summary>Forwards to the <see cref="AuthenticationProperties"/> overload, which carries the actual deferral logic.</summary>
	public override async Task SignInWithClaimsAsync(NorseUser user, bool isPersistent, IEnumerable<Claim> additionalClaims) =>
		await SignInWithClaimsAsync(user, new AuthenticationProperties { IsPersistent = isPersistent }, additionalClaims).ConfigureAwait(false);

	/// <summary>Signs in normally when the response can still write a cookie; otherwise stashes the sign-in via <see cref="IDeferredSignIn"/> and records the completion key on <see cref="DeferredSignInKeyItemName"/>.</summary>
	public override async Task SignInWithClaimsAsync(NorseUser user, AuthenticationProperties? authenticationProperties, IEnumerable<Claim> additionalClaims)
	{
		if (!Context.Response.HasStarted)
		{
			await base.SignInWithClaimsAsync(user, authenticationProperties, additionalClaims).ConfigureAwait(false);
			return;
		}

		var principal = await CreateUserPrincipalAsync(user).ConfigureAwait(false);
		((ClaimsIdentity)principal.Identity!).AddClaims(additionalClaims);
		var key = deferredSignIn.StashSignIn(AuthenticationScheme, principal, authenticationProperties ?? new AuthenticationProperties());
		Context.Items[DeferredSignInKeyItemName] = key;
	}

	/// <summary>Signs out normally when the response can still write a cookie; otherwise stashes the sign-out via <see cref="IDeferredSignIn"/> and records the completion key on <see cref="DeferredSignInKeyItemName"/>.</summary>
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

	// The base class's own 2FA-required branch does NOT funnel through SignInWithClaimsAsync (or any
	// other overridable seam) at all -- verified against the real installed Microsoft.AspNetCore.Identity
	// assembly (ilspycmd decompile of SignInManager<TUser>.SignInOrTwoFactorAsync, .NET 11 preview 6):
	// when a second factor is required it writes the partial two-factor cookie via a raw
	// `Context.SignInAsync(IdentityConstants.TwoFactorUserIdScheme, StoreTwoFactorInfo(userId,
	// loginProvider))` call, bypassing SignInWithClaimsAsync entirely. On an established circuit that
	// throws before SignInResult.TwoFactorRequired is ever returned to the caller -- the two overrides
	// above do not cover this path, so it needs its own. `StoreTwoFactorInfo` itself is `internal` on
	// the base class (inaccessible across the assembly boundary), so its exact claims shape is
	// reproduced here rather than called -- verify that claim yourself too if in doubt.
	/// <summary>
	/// Delegates to the base class unless a second factor is genuinely required AND the response has
	/// already started (an established Blazor Server circuit) -- in that one case, defers the partial
	/// two-factor sign-in via <see cref="IDeferredSignIn"/> instead of letting the base class's raw
	/// cookie write throw, reusing <see cref="DeferredSignInKeyItemName"/> so callers (e.g.
	/// <c>LoginHandler</c>) find it the same way they already do for a completed sign-in.
	/// </summary>
	protected override async Task<SignInResult> SignInOrTwoFactorAsync(NorseUser user, bool isPersistent, string? loginProvider = null, bool bypassTwoFactor = false)
	{
		var requiresTwoFactor = !bypassTwoFactor
			&& await IsTwoFactorEnabledAsync(user).ConfigureAwait(false)
			&& !await IsTwoFactorClientRememberedAsync(user).ConfigureAwait(false);

		if (!requiresTwoFactor || !Context.Response.HasStarted)
			return await base.SignInOrTwoFactorAsync(user, isPersistent, loginProvider, bypassTwoFactor).ConfigureAwait(false);

		if (await schemes.GetSchemeAsync(IdentityConstants.TwoFactorUserIdScheme).ConfigureAwait(false) is not null)
		{
			var userId = await UserManager.GetUserIdAsync(user).ConfigureAwait(false);
			var principal = StoreTwoFactorInfo(userId, loginProvider);
			var key = deferredSignIn.StashSignIn(IdentityConstants.TwoFactorUserIdScheme, principal, new AuthenticationProperties());
			Context.Items[DeferredSignInKeyItemName] = key;
		}

		return SignInResult.TwoFactorRequired;
	}

	// Mirrors the base class's own internal `StoreTwoFactorInfo` claims shape exactly (same scheme as
	// the ClaimsIdentity's authentication type, same two claim types) -- that method is `internal` on
	// Microsoft.AspNetCore.Identity's assembly, not reachable from here, so this reproduces it rather
	// than calling it. Getting this shape wrong would make LoginWith2fa's later
	// SignInManager.GetTwoFactorAuthenticationUserAsync() (RetrieveTwoFactorInfoAsync's cookie-read
	// fallback) fail to find the name claim it looks for.
	static ClaimsPrincipal StoreTwoFactorInfo(string userId, string? loginProvider)
	{
		ClaimsIdentity identity = new(IdentityConstants.TwoFactorUserIdScheme);
		identity.AddClaim(new Claim(ClaimTypes.Name, userId));
		if (loginProvider is not null)
			identity.AddClaim(new Claim(ClaimTypes.AuthenticationMethod, loginProvider));
		return new ClaimsPrincipal(identity);
	}

	/// <summary>
	/// Folds a destroyed key into a clean dead-session verdict. Law: a destroyed key IS a dead
	/// session -- the shred ceremony's (<c>Norse.Identity.Web.Server.ErasureService</c>) third act
	/// destroys the subject's key, and every subsequent attempt to re-materialize the row's
	/// protected columns (<c>Email</c>, <c>UserName</c>, both still wired through
	/// <see cref="NorsePersonalDataProtector"/>'s EF value converter) throws
	/// <see cref="KeyDestroyedException"/>, unwrapped, straight out of EF's materializer -- including
	/// from <c>UserManager.GetUserAsync</c>, which the base implementation calls to re-hydrate the
	/// principal's subject. Left uncaught, a shredded subject's surviving cookie 500-loops out of the
	/// cookie authentication middleware on every request instead of being rejected cleanly. This
	/// catch is deliberately narrow: it lives ONLY at this revalidation boundary. Every other path
	/// (<see cref="NorseUserStore"/>, <see cref="NorsePersonalDataProtector"/> itself) must keep
	/// throwing -- the disclosure surface's <c>Erased</c> fold (a later task) depends on the
	/// exception surviving there, and catching it earlier would silence that signal for good.
	/// </summary>
	public override async Task<NorseUser?> ValidateSecurityStampAsync(ClaimsPrincipal? principal)
	{
		try
		{
			return await base.ValidateSecurityStampAsync(principal).ConfigureAwait(false);
		}
		catch (KeyDestroyedException)
		{
			return null;
		}
	}
}
