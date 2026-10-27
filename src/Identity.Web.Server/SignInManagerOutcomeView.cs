using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;

namespace Norse.Identity.Web.Server;

/// <summary>
///     <c>signInManager.Outcome</c> (2026-10-24 explicit-writes spec §4.12): the stock <see cref="SignInManager{TUser}" />,
///     answering <see cref="Outcome{T}" /> through <see cref="IdentityOutcomeMap" />. It lives here, not in
///     <c>Identity.Outcomes</c>, because <c>SignInManager</c> lives in the ASP.NET Core shared framework, which the
///     migrations service must never take.
/// </summary>
/// <param name="signInManager">The manager this view wraps.</param>
sealed class SignInManagerOutcomeView(SignInManager<NorseUser> signInManager)
{
	/// <summary>
	///     Wraps <see cref="SignInManager{TUser}.PasswordSignInAsync(string, string, bool, bool)" />. An indeterminate
	///     access-failed increment (spec §4.5) answers <see cref="ErrorCategory.Indeterminate" />, and a destroyed key
	///     <see cref="ErrorCategory.Erased" />: outcomes, never exceptions.
	/// </summary>
	/// <param name="userName">The user name.</param>
	/// <param name="password">The password to check.</param>
	/// <param name="isPersistent">Whether the sign-in cookie persists.</param>
	/// <param name="lockoutOnFailure">Whether a failure counts toward lockout.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes the request's own cancellation.
	/// </param>
	public async ValueTask<Outcome<SignInCompletion>> PasswordSignInAsync(string userName, string password,
		bool isPersistent, bool lockoutOnFailure, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		try
		{
			return IdentityOutcomeMap.ToOutcome(await signInManager
				.PasswordSignInAsync(userName, password, isPersistent, lockoutOnFailure)
				.ConfigureAwait(false));
		}
		catch (Exception exception) when (IdentityOutcomeMap.TryClassify(exception, out var problem))
		{
			return new(new Failed(problem));
		}
	}
	/// <summary>
	///     Wraps <see cref="NorseSignInManager.TwoFactorChallengeSignInAsync" />: completes a parked two-factor
	///     challenge with an authenticator code. A destroyed key (an erased subject) answers
	///     <see cref="ErrorCategory.Erased" />, and an indeterminate write <see cref="ErrorCategory.Indeterminate" />.
	/// </summary>
	/// <param name="token">The challenge token <see cref="NorseSignInManager" /> parked.</param>
	/// <param name="code">The authenticator code.</param>
	/// <param name="rememberClient">Whether to remember this client so the second factor is not asked again.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes the request's own cancellation.
	/// </param>
	/// <exception cref="InvalidOperationException">The wrapped manager is not a <see cref="NorseSignInManager" />.</exception>
	public async ValueTask<Outcome<SignInCompletion>> TwoFactorChallengeSignInAsync(string token, string code,
		bool rememberClient, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		try
		{
			return signInManager is NorseSignInManager norse ?
				IdentityOutcomeMap.ToOutcome(await norse
					.TwoFactorChallengeSignInAsync(token, code, rememberClient)
					.ConfigureAwait(false)) :
				throw new InvalidOperationException($"{nameof(TwoFactorChallengeSignInAsync)} requires NorseSignInManager");
		}
		catch (Exception exception) when (IdentityOutcomeMap.TryClassify(exception, out var problem))
		{
			return new(new Failed(problem));
		}
	}

	/// <summary>
	///     Wraps <see cref="NorseSignInManager.RecoveryCodeChallengeSignInAsync" />: completes a parked two-factor
	///     challenge with a recovery code. A destroyed key (an erased subject) answers
	///     <see cref="ErrorCategory.Erased" />, and an indeterminate write <see cref="ErrorCategory.Indeterminate" />.
	/// </summary>
	/// <param name="token">The challenge token <see cref="NorseSignInManager" /> parked.</param>
	/// <param name="code">The recovery code.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes the request's own cancellation.
	/// </param>
	/// <exception cref="InvalidOperationException">The wrapped manager is not a <see cref="NorseSignInManager" />.</exception>
	public async ValueTask<Outcome<SignInCompletion>> RecoveryCodeChallengeSignInAsync(string token, string code,
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		try
		{
			return signInManager is NorseSignInManager norse ?
				IdentityOutcomeMap.ToOutcome(await norse
					.RecoveryCodeChallengeSignInAsync(token, code)
					.ConfigureAwait(false)) :
				throw new InvalidOperationException($"{nameof(RecoveryCodeChallengeSignInAsync)} requires NorseSignInManager");
		}
		catch (Exception exception) when (IdentityOutcomeMap.TryClassify(exception, out var problem))
		{
			return new(new Failed(problem));
		}
	}
}
