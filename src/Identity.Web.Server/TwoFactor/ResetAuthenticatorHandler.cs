using System.Data.Common;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components.Shared;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.TwoFactor;

/// <summary>
///     Disables two-factor authentication, then replaces the authenticator key, then refreshes the sign-in, answering
///     the setup page with <see cref="ManageStatus.AuthenticatorReset" /> so the caller can enroll the new key. Both
///     writes rotate the stamp.
/// </summary>
/// <remarks>
///     T3-35: once the disable succeeded or is indeterminate, any later failure -- the disable's indeterminate result
///     itself, a failed key reset, or the definite database failure the store rethrows (spec §4.8) -- re-reads and
///     refreshes through <see cref="AccountCaller.RefreshFromReReadAsync" /> and lands on the two-factor page with no
///     status key, which shows the truth on load. A definite disable failure writes no key, refreshes nothing and
///     passes through. The stock order means a failed key reset leaves two-factor off with the old key still stored:
///     the page shows that truth, and the caller enrolls again.
/// </remarks>
/// <param name="caller">Resolves the calling user from the principal, and re-reads it after a failure.</param>
/// <param name="userManager">Disables two-factor and resets the key.</param>
/// <param name="signInManager">Refreshes the caller's sign-in after the stamp rotation.</param>
/// <param name="deferredCompletion">Builds the completion detour for whatever the refresh stashed.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
/// <param name="logger">Records a key reset's database failure, which the answer handles but never shows.</param>
sealed partial class ResetAuthenticatorHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	SignInManager<NorseUser> signInManager,
	DeferredCompletion deferredCompletion,
	IHttpContextAccessor httpContextAccessor,
	ILogger<ResetAuthenticatorHandler> logger)
	: IRequestHandler<ResetAuthenticatorCommand, NavigationResult>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(ResetAuthenticatorCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> success);
		var user = success.Value;

		var pathBase = httpContextAccessor.HttpContext!.Request.PathBase;
		var disabled = await userManager.Outcome.SetTwoFactorEnabledAsync(user, false, cancellationToken).ConfigureAwait(false);
		var indeterminate = false;
		if (disabled.TryGetValue(out Failed failed))
		{
			if (failed.Problem.Category is not ErrorCategory.Indeterminate)
				return new(failed);
			indeterminate = true;
		}

		if (indeterminate || !await ResetKeyAsync(user, cancellationToken).ConfigureAwait(false))
			return await caller.RefreshFromReReadAsync(signInManager, deferredCompletion,
				UriHelper.BuildRelative(pathBase, "/Account/Manage/TwoFactorAuthentication"), cancellationToken).ConfigureAwait(false);

		await signInManager.RefreshSignInAsync(user).ConfigureAwait(false);
		var url = ManageUrls.Status(pathBase, "/Account/Manage/EnableAuthenticator", ManageStatus.AuthenticatorReset);
		return Outcome<NavigationResult>.Ok(new NavigationResult { NextUrl = deferredCompletion.TryBuildUrl(url) ?? url });
	}

	/// <summary>The key reset; <see langword="false" /> for any failure, the store's rethrown definite one included.</summary>
	async Task<bool> ResetKeyAsync(NorseUser user, CancellationToken cancellationToken)
	{
		try
		{
			return (await userManager.Outcome.ResetAuthenticatorKeyAsync(user, cancellationToken).ConfigureAwait(false))
				.TryGetValue(out Success<Unit> _);
		}
		catch (DbException exception)
		{
			LogKeyResetFailed(logger, exception);
			return false;
		}
	}

	[LoggerMessage(Level = LogLevel.Warning,
		Message = "Resetting the authenticator key failed in the database; two-factor is off and the old key is still stored.")]
	static partial void LogKeyResetFailed(ILogger logger, Exception exception);
}
