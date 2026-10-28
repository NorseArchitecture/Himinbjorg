using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.TwoFactor;

/// <summary>
///     Replaces the caller's recovery codes with a fresh batch of ten and answers them in place. A caller with
///     two-factor off is refused and nothing is written. Replacing codes never rotates the stamp, so nothing is
///     refreshed, and every failure -- an indeterminate replacement included -- passes through unchanged.
/// </summary>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="userManager">Reads the two-factor flag and replaces the codes.</param>
sealed class GenerateRecoveryCodesHandler(AccountCaller caller, UserManager<NorseUser> userManager)
	: IRequestHandler<GenerateRecoveryCodesCommand, RecoveryCodesResponse>
{
	/// <summary>The stock batch of ten.</summary>
	const int RecoveryCodeCount = 10;

	static readonly Failed _notEnabled = new(Problem.ModelError(ErrorCategory.Validation,
		"Cannot generate recovery codes because two-factor authentication is not enabled."));

	/// <inheritdoc />
	public async ValueTask<Outcome<RecoveryCodesResponse>> Handle(GenerateRecoveryCodesCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> success);
		var user = success.Value;

		if (!await userManager.GetTwoFactorEnabledAsync(user).ConfigureAwait(false))
			return new(_notEnabled);

		var replaced = await userManager.Outcome.ReplaceRecoveryCodesAsync(user, RecoveryCodeCount, cancellationToken)
			.ConfigureAwait(false);
		if (replaced.TryGetValue(out Failed failed))
			return new(failed);
		replaced.TryGetValue(out Success<string[]> codes);
		return Outcome<RecoveryCodesResponse>.Ok(new RecoveryCodesResponse { RecoveryCodes = codes.Value });
	}
}
