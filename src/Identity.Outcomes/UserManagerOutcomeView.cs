using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Outcomes;

/// <summary>
///     <c>userManager.Outcome</c> (2026-10-24 explicit-writes spec §4.12): the stock <see cref="UserManager{TUser}" />,
///     answering <see cref="Outcome{T}" /> through <see cref="IdentityOutcomeMap" />. Each method keeps the name of the
///     manager method it wraps.
/// </summary>
/// <param name="userManager">The manager this view wraps.</param>
public sealed class UserManagerOutcomeView(UserManager<NorseUser> userManager)
{
	/// <summary>Wraps <see cref="UserManager{TUser}.CreateAsync(TUser, string)" />.</summary>
	/// <param name="user">The user to create.</param>
	/// <param name="password">The user's password.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes its own <c>CancellationToken</c>.
	/// </param>
	public ValueTask<Outcome<Unit>> CreateAsync(NorseUser user, string password,
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		return IdentityOutcomeMap.GuardAsync(async () =>
			IdentityOutcomeMap.ToOutcome(await userManager.CreateAsync(user, password).ConfigureAwait(false),
				Unit.Value));
	}

	/// <summary>
	///     Wraps <see cref="UserManager{TUser}.FindByEmailAsync" />: <see cref="ErrorCategory.NotFound" /> for no such
	///     user, and <see cref="ErrorCategory.Erased" /> with the receipt for a user whose key is destroyed.
	/// </summary>
	/// <param name="email">The email to look up.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes its own <c>CancellationToken</c>.
	/// </param>
	public ValueTask<Outcome<NorseUser>> FindByEmailAsync(string email, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		return IdentityOutcomeMap.GuardAsync(async () =>
			await userManager.FindByEmailAsync(email).ConfigureAwait(false) is { } user ?
				Outcome<NorseUser>.Ok(user) :
				Outcome<NorseUser>.Err(ErrorCategory.NotFound));
	}

	/// <summary>
	///     Wraps <see cref="UserManager{TUser}.GetUserAsync" />: <see cref="ErrorCategory.NotFound" /> for a principal
	///     naming no user, and <see cref="ErrorCategory.Erased" /> with the receipt for a user whose key is destroyed.
	/// </summary>
	/// <param name="principal">The principal whose user to load.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes its own <c>CancellationToken</c>.
	/// </param>
	public ValueTask<Outcome<NorseUser>> GetUserAsync(ClaimsPrincipal principal,
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		return IdentityOutcomeMap.GuardAsync(async () =>
			await userManager.GetUserAsync(principal).ConfigureAwait(false) is { } user ?
				Outcome<NorseUser>.Ok(user) :
				Outcome<NorseUser>.Err(ErrorCategory.NotFound));
	}

	/// <summary>
	///     Wraps <see cref="UserManager{TUser}.FindByIdAsync" />: <see cref="ErrorCategory.NotFound" /> for no such
	///     user, and <see cref="ErrorCategory.Erased" /> with the receipt for a user whose key is destroyed.
	/// </summary>
	/// <param name="userId">The id to look up.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes its own <c>CancellationToken</c>.
	/// </param>
	public ValueTask<Outcome<NorseUser>> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		return IdentityOutcomeMap.GuardAsync(async () =>
			await userManager.FindByIdAsync(userId).ConfigureAwait(false) is { } user ?
				Outcome<NorseUser>.Ok(user) :
				Outcome<NorseUser>.Err(ErrorCategory.NotFound));
	}

	/// <summary>Wraps <see cref="UserManager{TUser}.ResetPasswordAsync" />.</summary>
	/// <param name="user">The user whose password to reset.</param>
	/// <param name="token">The password-reset token.</param>
	/// <param name="newPassword">The new password.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes its own <c>CancellationToken</c>.
	/// </param>
	public ValueTask<Outcome<Unit>> ResetPasswordAsync(NorseUser user, string token, string newPassword,
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		return IdentityOutcomeMap.GuardAsync(async () =>
			IdentityOutcomeMap.ToOutcome(
				await userManager.ResetPasswordAsync(user, token, newPassword).ConfigureAwait(false), Unit.Value));
	}

	/// <summary>Wraps <see cref="UserManager{TUser}.ConfirmEmailAsync" />.</summary>
	/// <param name="user">The user whose email to confirm.</param>
	/// <param name="token">The email-confirmation token.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes its own <c>CancellationToken</c>.
	/// </param>
	public ValueTask<Outcome<Unit>> ConfirmEmailAsync(NorseUser user, string token,
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		return IdentityOutcomeMap.GuardAsync(async () =>
			IdentityOutcomeMap.ToOutcome(await userManager.ConfirmEmailAsync(user, token).ConfigureAwait(false),
				Unit.Value));
	}

	/// <summary>Wraps <see cref="UserManager{TUser}.ChangeEmailAsync" />.</summary>
	/// <param name="user">The user whose email to change.</param>
	/// <param name="newEmail">The new email address.</param>
	/// <param name="token">The change-email token.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes its own <c>CancellationToken</c>.
	/// </param>
	public ValueTask<Outcome<Unit>> ChangeEmailAsync(NorseUser user, string newEmail, string token,
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		return IdentityOutcomeMap.GuardAsync(async () =>
			IdentityOutcomeMap.ToOutcome(
				await userManager.ChangeEmailAsync(user, newEmail, token).ConfigureAwait(false), Unit.Value));
	}

	/// <summary>
	///     Wraps <see cref="IRecoveryCodeReplacement.ReplaceRecoveryCodesAsync" />: the new codes on success, and the
	///     update's own failure otherwise, so an indeterminate commit answers <see cref="ErrorCategory.Indeterminate" />
	///     instead of the <see langword="null" /> <see cref="UserManager{TUser}.GenerateNewTwoFactorRecoveryCodesAsync" />
	///     answers for every failure.
	/// </summary>
	/// <param name="user">The user whose codes to replace.</param>
	/// <param name="number">How many codes to generate.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes its own <c>CancellationToken</c>.
	/// </param>
	/// <exception cref="InvalidOperationException">
	///     The manager is not an <see cref="IRecoveryCodeReplacement" /> (a stock <see cref="UserManager{TUser}" />).
	/// </exception>
	public ValueTask<Outcome<string[]>> ReplaceRecoveryCodesAsync(NorseUser user, int number,
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		var lossless = userManager as IRecoveryCodeReplacement ??
			throw new InvalidOperationException(
				"ReplaceRecoveryCodesAsync requires NorseUserManager: a stock UserManager cannot report a recovery-code replacement's own result.");
		return IdentityOutcomeMap.GuardAsync(async () =>
		{
			var (result, codes) = await lossless.ReplaceRecoveryCodesAsync(user, number).ConfigureAwait(false);
			return IdentityOutcomeMap.ToOutcome(result, codes);
		});
	}
}
