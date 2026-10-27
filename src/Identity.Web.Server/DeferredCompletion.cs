using Norse.Abstractions.Web.Server.DeferredSignIn;

namespace Norse.Identity.Web.Server;

/// <summary>
///     Turns whatever <see cref="NorseSignInManager" /> stashed on <c>HttpContext.Items</c> during this
///     request into the one <c>/_auth/complete</c> detour that finishes it. Only ever populated on the
///     Blazor-Server in-process path (a circuit that could not Set-Cookie because the response had already
///     started) -- a real gRPC/WASM call never stashes, so <see cref="TryBuildUrl" /> answers
///     <see langword="null" /> there without any channel-specific branching.
/// </summary>
/// <param name="deferredSignIn">Builds each completion URL from a stash key.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>Items</c>.</param>
sealed class DeferredCompletion(IDeferredSignIn deferredSignIn, IHttpContextAccessor httpContextAccessor)
{
	/// <summary>
	///     Builds the completion URL for this request's stashes, landing on <paramref name="returnUrl" />.
	///     The identity stash (<see cref="NorseSignInManager.DeferredSignInKeyItemName" />) and the
	///     remember-machine stash (<see cref="NorseSignInManager.DeferredRememberClientKeyItemName" />) each
	///     wrap the return URL once; with both present they chain, the identity completion outside and the
	///     remember completion inside (spec §5.4).
	/// </summary>
	/// <param name="returnUrl">Where the browser lands once every stash has completed.</param>
	/// <returns>The completion URL, or <see langword="null" /> when nothing was stashed.</returns>
	public string? TryBuildUrl(string returnUrl)
	{
		var items = httpContextAccessor.HttpContext!.Items;
		var identityKey = items[NorseSignInManager.DeferredSignInKeyItemName] as string;
		var rememberKey = items[NorseSignInManager.DeferredRememberClientKeyItemName] as string;

		// The remember stash wraps the return URL first, so the identity completion -- outermost -- runs first.
		var landing = rememberKey is null ?
			returnUrl :
			deferredSignIn.BuildCompletionUrl(rememberKey, returnUrl);
		if (identityKey is not null)
			return deferredSignIn.BuildCompletionUrl(identityKey, landing);

		return rememberKey is null ?
			null :
			landing;
	}
}
