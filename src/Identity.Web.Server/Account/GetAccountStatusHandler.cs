using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Account;

/// <summary>
///     Answers the caller's account state: the facts the account pages branch their rendering on, every one a
///     read-only manager call (raw by law, §5.2). The caller comes from the principal, never the request; a principal
///     naming no user answers <see cref="ErrorCategory.NotFound" /> and an erased one
///     <see cref="ErrorCategory.Erased" />, both passed through unchanged.
/// </summary>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="userManager">Reads the account facts.</param>
/// <param name="signInManager">Reads whether the calling machine is remembered for two-factor purposes.</param>
sealed class GetAccountStatusHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	SignInManager<NorseUser> signInManager)
	: IRequestHandler<GetAccountStatusCommand, AccountStatusResponse>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<AccountStatusResponse>> Handle(GetAccountStatusCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed failed))
			return new(failed);
		found.TryGetValue(out Success<NorseUser> success);
		var user = success.Value;

		return Outcome<AccountStatusResponse>.Ok(new AccountStatusResponse
		{
			HasPassword = await userManager.HasPasswordAsync(user).ConfigureAwait(false),
			EmailConfirmed = await userManager.IsEmailConfirmedAsync(user).ConfigureAwait(false),
			TwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(user).ConfigureAwait(false),
			HasAuthenticator = await userManager.GetAuthenticatorKeyAsync(user).ConfigureAwait(false) is not null,
			RecoveryCodesLeft = await userManager.CountRecoveryCodesAsync(user).ConfigureAwait(false),
			IsMachineRemembered = await signInManager.IsTwoFactorClientRememberedAsync(user).ConfigureAwait(false),
			PasskeyCount = (await userManager.GetPasskeysAsync(user).ConfigureAwait(false)).Count,
			ExternalLoginCount = (await userManager.GetLoginsAsync(user).ConfigureAwait(false)).Count
		});
	}
}
