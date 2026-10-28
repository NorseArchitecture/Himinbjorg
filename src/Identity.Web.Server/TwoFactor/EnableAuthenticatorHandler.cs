using System.Data.Common;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components.Shared;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.TwoFactor;

/// <summary>
///     Verifies an authenticator code and enables two-factor authentication. The code is checked first, spaces and
///     hyphens stripped, and a wrong one writes nothing. Enabling rotates the stamp, so the sign-in is refreshed and
///     the answer navigates: when no recovery codes remain, ten are issued and ride a one-shot handoff to
///     <see cref="RecoveryCodesHandoff.Route" />, sealed with the stamp read after the writes; otherwise the two-factor
///     page with <see cref="ManageStatus.AuthenticatorVerified" />.
/// </summary>
/// <remarks>
///     T3-35: once the enable succeeded or is indeterminate, every later failure re-reads and refreshes through
///     <see cref="AccountCaller.RefreshFromReReadAsync" />. An indeterminate enable lands on the two-factor page with no
///     status key, which shows the truth on load; a failed code step lands there with
///     <see cref="ManageStatus.RecoveryCodesFailed" />. A definite enable failure refreshes nothing and passes through.
/// </remarks>
/// <param name="caller">Resolves the calling user from the principal, and re-reads it after a failure.</param>
/// <param name="userManager">Verifies the code, enables two-factor and issues the codes.</param>
/// <param name="signInManager">Refreshes the caller's sign-in after the stamp rotation.</param>
/// <param name="deferredCompletion">Builds the completion detour for whatever the refresh stashed.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
/// <param name="dataProtectionProvider">Seals the recovery-codes handoff.</param>
/// <param name="logger">Records a code step's database failure, which the answer handles but never shows.</param>
sealed partial class EnableAuthenticatorHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	SignInManager<NorseUser> signInManager,
	DeferredCompletion deferredCompletion,
	IHttpContextAccessor httpContextAccessor,
	IDataProtectionProvider dataProtectionProvider,
	ILogger<EnableAuthenticatorHandler> logger)
	: IRequestHandler<EnableAuthenticatorCommand, NavigationResult>
{
	/// <summary>The recovery codes issued with a first enable: the stock batch of ten.</summary>
	const int RecoveryCodeCount = 10;

	const string TwoFactorRoute = "/Account/Manage/TwoFactorAuthentication";

	static readonly Failed _invalidCode = new(new Problem
	{
		Category = ErrorCategory.Validation,
		Errors = new Dictionary<string, string[]> { [nameof(EnableAuthenticatorRequest.Code)] = ["Verification code is invalid."] }
	});

	readonly ITimeLimitedDataProtector _handoffProtector =
		dataProtectionProvider.CreateProtector(RecoveryCodesHandoff.Purpose).ToTimeLimitedDataProtector();

	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(EnableAuthenticatorCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> success);
		var user = success.Value;

		var code = request.Request.Code.Replace(" ", string.Empty, StringComparison.Ordinal)
			.Replace("-", string.Empty, StringComparison.Ordinal);
		if (!await userManager.VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, code)
				.ConfigureAwait(false))
			return new(_invalidCode);

		var pathBase = httpContextAccessor.HttpContext!.Request.PathBase;
		var enabled = await userManager.Outcome.SetTwoFactorEnabledAsync(user, true, cancellationToken).ConfigureAwait(false);
		if (enabled.TryGetValue(out Failed failed))
			return failed.Problem.Category is ErrorCategory.Indeterminate ?
				await caller.RefreshFromReReadAsync(signInManager, deferredCompletion,
					UriHelper.BuildRelative(pathBase, TwoFactorRoute), cancellationToken).ConfigureAwait(false) :
				new(failed);

		string url;
		if (await userManager.CountRecoveryCodesAsync(user).ConfigureAwait(false) is not 0)
			url = ManageUrls.Status(pathBase, TwoFactorRoute, ManageStatus.AuthenticatorVerified);
		else if (await ReplaceCodesAsync(user, cancellationToken).ConfigureAwait(false) is { } codes)
			url = UriHelper.BuildRelative(pathBase, RecoveryCodesHandoff.Route, QueryString.Create("handoff",
				RecoveryCodesHandoff.Protect(_handoffProtector, await userManager.GetUserIdAsync(user).ConfigureAwait(false),
					await userManager.GetSecurityStampAsync(user).ConfigureAwait(false) ?? string.Empty, codes)));
		else
			return await caller.RefreshFromReReadAsync(signInManager, deferredCompletion,
				ManageUrls.Status(pathBase, TwoFactorRoute, ManageStatus.RecoveryCodesFailed), cancellationToken).ConfigureAwait(false);

		await signInManager.RefreshSignInAsync(user).ConfigureAwait(false);
		return Outcome<NavigationResult>.Ok(new NavigationResult { NextUrl = deferredCompletion.TryBuildUrl(url) ?? url });
	}

	/// <summary>
	///     The code step: the new codes, or <see langword="null" /> for any failure -- a mapped one, or the definite
	///     database failure the store rethrows (spec §4.8), which wrote nothing but follows an enable that committed.
	/// </summary>
	async Task<string[]?> ReplaceCodesAsync(NorseUser user, CancellationToken cancellationToken)
	{
		try
		{
			var replaced = await userManager.Outcome.ReplaceRecoveryCodesAsync(user, RecoveryCodeCount, cancellationToken)
				.ConfigureAwait(false);
			return replaced.TryGetValue(out Success<string[]> codes) ?
				codes.Value :
				null;
		}
		catch (DbException exception)
		{
			LogCodeStepFailed(logger, exception);
			return null;
		}
	}

	[LoggerMessage(Level = LogLevel.Warning,
		Message = "Issuing recovery codes after enabling two-factor failed in the database; the enable stands and no codes were issued.")]
	static partial void LogCodeStepFailed(ILogger logger, Exception exception);
}
