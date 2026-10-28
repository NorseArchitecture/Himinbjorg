using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.TwoFactor;

/// <summary>
///     Reveals a recovery-codes handoff (T3-12) once (M10). It refuses, with one message, a handoff that does not
///     unprotect, that names another user, that was sealed under a stamp since rotated, or whose codes are no longer
///     exactly the stored set (replaced, or one redeemed). Only then is it consumed through the one-shot ledger, with
///     its raw payload and its own expiry (P5), and a second reveal answers that the codes were already shown.
/// </summary>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="userManager">Reads the caller's id, stamp and stored code set.</param>
/// <param name="dataProtectionProvider">Unprotects the handoff.</param>
/// <param name="ledger">Consumes the handoff once.</param>
sealed class RevealRecoveryCodesHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	IDataProtectionProvider dataProtectionProvider,
	IPasskeyChallengeLedger ledger)
	: IRequestHandler<RevealRecoveryCodesCommand, RecoveryCodesResponse>
{
	/// <summary>Stock Identity's login provider for the tokens it keeps itself, where the code set lives.</summary>
	const string InternalLoginProvider = "[AspNetUserStore]";

	/// <summary>Stock Identity's token name for the recovery-code set, stored <c>;</c>-joined.</summary>
	const string RecoveryCodeTokenName = "RecoveryCodes";

	static readonly Failed _unavailable =
		new(Problem.ModelError(ErrorCategory.Validation, "These recovery codes are no longer available."));

	static readonly Failed _alreadyShown =
		new(Problem.ModelError(ErrorCategory.Validation, "These recovery codes have already been shown."));

	readonly ITimeLimitedDataProtector _handoffProtector =
		dataProtectionProvider.CreateProtector(RecoveryCodesHandoff.Purpose).ToTimeLimitedDataProtector();

	/// <inheritdoc />
	public async ValueTask<Outcome<RecoveryCodesResponse>> Handle(RevealRecoveryCodesCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> success);
		var user = success.Value;

		if (!RecoveryCodesHandoff.TryUnprotect(_handoffProtector, request.Request.Handoff, out var opened) ||
			!string.Equals(opened.UserId, await userManager.GetUserIdAsync(user).ConfigureAwait(false), StringComparison.Ordinal) ||
			!string.Equals(opened.SecurityStamp, await userManager.GetSecurityStampAsync(user).ConfigureAwait(false),
				StringComparison.Ordinal) ||
			!string.Equals(string.Join(';', opened.Codes),
				await userManager.GetAuthenticationTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName).ConfigureAwait(false),
				StringComparison.Ordinal))
			return new(_unavailable);

		if (!await ledger.TryConsumeAsync(opened.Payload, opened.ExpiresAt, cancellationToken).ConfigureAwait(false))
			return new(_alreadyShown);

		return Outcome<RecoveryCodesResponse>.Ok(new RecoveryCodesResponse { RecoveryCodes = [.. opened.Codes] });
	}
}
