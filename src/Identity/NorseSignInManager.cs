using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Norse.Infrastructure.Web.Server.DeferredSignIn;

namespace Norse.Identity;

/// <summary>
/// Overrides every seam ASP.NET Core Identity's sign-in/sign-out paths funnel through to detect when the
/// caller is an already-established Blazor Server interactive circuit (<c>Context.Response.HasStarted</c>)
/// — cookie writes are impossible there, not merely inconvenient. When detected, defers via
/// <see cref="IDeferredSignIn"/> instead of writing the cookie directly and stashes the completion key on
/// <c>HttpContext.Items</c> for the caller to read back. Every other call path (WASM/MAUI over gRPC-Web,
/// any static-SSR request) is a real, distinct HTTP request with <c>Response.HasStarted == false</c> and
/// behaves exactly as the unmodified base class would — zero behavior change for those paths.
/// </summary>
public sealed class NorseSignInManager(
	UserManager<NorseUser> userManager, IHttpContextAccessor contextAccessor,
	IUserClaimsPrincipalFactory<NorseUser> claimsFactory, IOptions<IdentityOptions> optionsAccessor,
	ILogger<SignInManager<NorseUser>> logger, IAuthenticationSchemeProvider schemes,
	IUserConfirmation<NorseUser> confirmation, IDeferredSignIn deferredSignIn)
	: SignInManager<NorseUser>(userManager, contextAccessor, claimsFactory, optionsAccessor, logger, schemes, confirmation)
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
}
