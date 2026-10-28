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
	static readonly Failed _attestationFailed =
		new(Problem.ModelError(ErrorCategory.Validation, NorseSignInManager.AttestationFailedMessage));

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
	///     Wraps <see cref="SignInManager{TUser}.ExternalLoginSignInAsync(string, string, bool, bool)" />, never bypassing
	///     two-factor: an account with two-factor enabled answers <see cref="SignInCompletion.RequiresTwoFactor" />,
	///     whatever the provider asserted. A destroyed key answers <see cref="ErrorCategory.Erased" />, and an
	///     indeterminate write <see cref="ErrorCategory.Indeterminate" />.
	/// </summary>
	/// <param name="loginProvider">The external login's provider.</param>
	/// <param name="providerKey">The external login's provider key.</param>
	/// <param name="isPersistent">Whether the sign-in cookie persists.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes the request's own cancellation.
	/// </param>
	public async ValueTask<Outcome<SignInCompletion>> ExternalLoginSignInAsync(string loginProvider, string providerKey,
		bool isPersistent, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		try
		{
			return IdentityOutcomeMap.ToOutcome(await signInManager
				.ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent, bypassTwoFactor: false)
				.ConfigureAwait(false));
		}
		catch (Exception exception) when (IdentityOutcomeMap.TryClassify(exception, out var problem))
		{
			return new(new Failed(problem));
		}
	}

	/// <summary>
	///     Wraps <see cref="NorseSignInManager.TwoFactorChallengeSignInAsync" />: completes a parked two-factor
	///     challenge with an authenticator code, answering the landing the challenge carried. A destroyed key (an erased subject) answers
	///     <see cref="ErrorCategory.Erased" />, and an indeterminate write <see cref="ErrorCategory.Indeterminate" />.
	/// </summary>
	/// <param name="token">The challenge token <see cref="NorseSignInManager" /> parked.</param>
	/// <param name="code">The authenticator code.</param>
	/// <param name="rememberClient">Whether to remember this client so the second factor is not asked again.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes the request's own cancellation.
	/// </param>
	/// <exception cref="InvalidOperationException">The wrapped manager is not a <see cref="NorseSignInManager" />.</exception>
	public async ValueTask<Outcome<string>> TwoFactorChallengeSignInAsync(string token, string code,
		bool rememberClient, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		try
		{
			return signInManager is NorseSignInManager norse ?
				Landing(await norse
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
	///     challenge with a recovery code, answering the landing the challenge carried. A destroyed key (an erased subject) answers
	///     <see cref="ErrorCategory.Erased" />, and an indeterminate write <see cref="ErrorCategory.Indeterminate" />.
	/// </summary>
	/// <param name="token">The challenge token <see cref="NorseSignInManager" /> parked.</param>
	/// <param name="code">The recovery code.</param>
	/// <param name="cancellationToken">
	///     Checked before the call; the manager itself observes the request's own cancellation.
	/// </param>
	/// <exception cref="InvalidOperationException">The wrapped manager is not a <see cref="NorseSignInManager" />.</exception>
	public async ValueTask<Outcome<string>> RecoveryCodeChallengeSignInAsync(string token, string code,
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		try
		{
			return signInManager is NorseSignInManager norse ?
				Landing(await norse
					.RecoveryCodeChallengeSignInAsync(token, code)
					.ConfigureAwait(false)) :
				throw new InvalidOperationException($"{nameof(RecoveryCodeChallengeSignInAsync)} requires NorseSignInManager");
		}
		catch (Exception exception) when (IdentityOutcomeMap.TryClassify(exception, out var problem))
		{
			return new(new Failed(problem));
		}
	}

	/// <summary>
	///     Wraps <see cref="NorseSignInManager.CreatePasskeyOptionsAsync" />: begins a passkey registration for
	///     <paramref name="user" />. A destroyed key answers <see cref="ErrorCategory.Erased" />.
	/// </summary>
	/// <param name="user">The user registering a passkey.</param>
	/// <param name="cancellationToken">Checked before the call.</param>
	/// <exception cref="InvalidOperationException">The wrapped manager is not a <see cref="NorseSignInManager" />.</exception>
	public async ValueTask<Outcome<PasskeyCeremony>> MakePasskeyCreationOptionsAsync(NorseUser user,
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		try
		{
			return signInManager is NorseSignInManager norse ?
				Outcome<PasskeyCeremony>.Ok(await norse
					.CreatePasskeyOptionsAsync(user, cancellationToken)
					.ConfigureAwait(false)) :
				throw new InvalidOperationException($"{nameof(MakePasskeyCreationOptionsAsync)} requires NorseSignInManager");
		}
		catch (Exception exception) when (IdentityOutcomeMap.TryClassify(exception, out var problem))
		{
			return new(new Failed(problem));
		}
	}

	/// <summary>
	///     Wraps <see cref="NorseSignInManager.AttestPasskeyAsync" />: a verified attestation answers its result, and
	///     every refusal -- a bad state or the handler's own -- one <see cref="ErrorCategory.Validation" /> carrying
	///     <see cref="NorseSignInManager.AttestationFailedMessage" />, never the handler's message.
	/// </summary>
	/// <param name="credentialJson">The browser's attestation credential, as JSON.</param>
	/// <param name="attestationState">The protected state from <see cref="PasskeyCeremony.State" />.</param>
	/// <param name="cancellationToken">Checked before the call.</param>
	/// <exception cref="InvalidOperationException">The wrapped manager is not a <see cref="NorseSignInManager" />.</exception>
	public async ValueTask<Outcome<PasskeyAttestationResult>> PerformPasskeyAttestationAsync(string credentialJson,
		string attestationState, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		try
		{
			var result = signInManager is NorseSignInManager norse ?
				await norse.AttestPasskeyAsync(credentialJson, attestationState, cancellationToken).ConfigureAwait(false) :
				throw new InvalidOperationException($"{nameof(PerformPasskeyAttestationAsync)} requires NorseSignInManager");
			return result.Succeeded ?
				Outcome<PasskeyAttestationResult>.Ok(result) :
				new(_attestationFailed);
		}
		catch (Exception exception) when (IdentityOutcomeMap.TryClassify(exception, out var problem))
		{
			return new(new Failed(problem));
		}
	}

	/// <summary>
	///     Wraps <see cref="NorseSignInManager.CreatePasskeyRequestOptionsAsync" />: begins a passkey sign-in.
	/// </summary>
	/// <param name="cancellationToken">Checked before the call.</param>
	/// <exception cref="InvalidOperationException">The wrapped manager is not a <see cref="NorseSignInManager" />.</exception>
	public async ValueTask<Outcome<PasskeyCeremony>> MakePasskeyRequestOptionsAsync(
		CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		try
		{
			return signInManager is NorseSignInManager norse ?
				Outcome<PasskeyCeremony>.Ok(await norse
					.CreatePasskeyRequestOptionsAsync(cancellationToken)
					.ConfigureAwait(false)) :
				throw new InvalidOperationException($"{nameof(MakePasskeyRequestOptionsAsync)} requires NorseSignInManager");
		}
		catch (Exception exception) when (IdentityOutcomeMap.TryClassify(exception, out var problem))
		{
			return new(new Failed(problem));
		}
	}

	/// <summary>
	///     Wraps <see cref="NorseSignInManager.PasskeyAssertionSignInAsync" />, mapping like
	///     <see cref="PasswordSignInAsync" />: every refusal of the state or the assertion, a replay included, answers
	///     <see cref="ErrorCategory.InvalidCredentials" />. A destroyed key answers <see cref="ErrorCategory.Erased" />,
	///     and an indeterminate write <see cref="ErrorCategory.Indeterminate" />.
	/// </summary>
	/// <param name="credentialJson">The browser's assertion credential, as JSON.</param>
	/// <param name="assertionState">The protected state from <see cref="PasskeyCeremony.State" />.</param>
	/// <param name="isPersistent">Whether the sign-in cookie persists.</param>
	/// <param name="cancellationToken">Checked before the call, and cancels the ledger consumption.</param>
	/// <exception cref="InvalidOperationException">The wrapped manager is not a <see cref="NorseSignInManager" />.</exception>
	public async ValueTask<Outcome<SignInCompletion>> PasskeyAssertionSignInAsync(string credentialJson,
		string assertionState, bool isPersistent, CancellationToken cancellationToken = default)
	{
		cancellationToken.ThrowIfCancellationRequested();
		try
		{
			return signInManager is NorseSignInManager norse ?
				IdentityOutcomeMap.ToOutcome(await norse
					.PasskeyAssertionSignInAsync(credentialJson, assertionState, isPersistent, cancellationToken)
					.ConfigureAwait(false)) :
				throw new InvalidOperationException($"{nameof(PasskeyAssertionSignInAsync)} requires NorseSignInManager");
		}
		catch (Exception exception) when (IdentityOutcomeMap.TryClassify(exception, out var problem))
		{
			return new(new Failed(problem));
		}
	}

	// A refusal maps through the one table; only a completed sign-in answers its landing. A challenge completion never
	// answers a second challenge, so anything else is a broken reproduction, not an outcome.
	static Outcome<string> Landing(ChallengeSignInResult result)
	{
		if (IdentityOutcomeMap.ToOutcome(result.Result).TryGetValue(out Failed failed))
			return new(failed);
		return result.Result.Succeeded ?
			Outcome<string>.Ok(result.ReturnUrl) :
			throw new InvalidOperationException("A challenge completion answered a second challenge");
	}
}
