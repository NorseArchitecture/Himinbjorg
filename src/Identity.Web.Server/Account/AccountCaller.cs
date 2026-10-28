using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Account;

/// <summary>
///     Resolves the account-tier caller: the user the principal names, never one the request names. Every account
///     handler starts here and passes a failure through unchanged -- a principal naming no user answers
///     <see cref="ErrorCategory.NotFound" />, and an erased one <see cref="ErrorCategory.Erased" /> with its receipt.
///     Each call reads the user afresh, so a handler that must re-read after a write calls it again, or
///     <see cref="RefreshFromReReadAsync" />.
/// </summary>
/// <param name="principalAccessor">Reaches the caller's principal.</param>
/// <param name="userManager">Loads the user the principal names.</param>
sealed class AccountCaller(IPrincipalAccessor principalAccessor, UserManager<NorseUser> userManager)
{
	/// <summary>Loads the caller's user.</summary>
	/// <param name="cancellationToken">Cancels the principal read and the lookup.</param>
	/// <returns>The caller's user, or the lookup's failure.</returns>
	public async ValueTask<Outcome<NorseUser>> ResolveAsync(CancellationToken cancellationToken = default)
	{
		var principal = await principalAccessor.GetPrincipalAsync(cancellationToken).ConfigureAwait(false);
		return await userManager.Outcome.GetUserAsync(principal, cancellationToken).ConfigureAwait(false);
	}

	/// <summary>
	///     T3-35, the one re-read-and-refresh: once a stamp-rotating write succeeded or is indeterminate, a later failure
	///     still refreshes the sign-in, or the old cookie dies at the next validation and signs the caller out. The
	///     refresh uses the user read afresh, never the as-read instance: a failed or indeterminate flush may have
	///     poisoned it, and its stamp may not be the one the database holds.
	/// </summary>
	/// <param name="signInManager">Refreshes the caller's sign-in.</param>
	/// <param name="deferredCompletion">Builds the completion detour for whatever the refresh stashed.</param>
	/// <param name="url">The root-relative, PathBase-qualified landing.</param>
	/// <param name="cancellationToken">Cancels the re-read.</param>
	/// <returns><paramref name="url" />, through the detour on a circuit; or the re-read's failure, with nothing refreshed.</returns>
	public async ValueTask<Outcome<NavigationResult>> RefreshFromReReadAsync(SignInManager<NorseUser> signInManager,
		DeferredCompletion deferredCompletion, string url, CancellationToken cancellationToken = default)
	{
		var reread = await ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (reread.TryGetValue(out Failed failed))
			return new(failed);
		reread.TryGetValue(out Success<NorseUser> user);

		await signInManager.RefreshSignInAsync(user.Value).ConfigureAwait(false);
		return Outcome<NavigationResult>.Ok(new NavigationResult { NextUrl = deferredCompletion.TryBuildUrl(url) ?? url });
	}
}
