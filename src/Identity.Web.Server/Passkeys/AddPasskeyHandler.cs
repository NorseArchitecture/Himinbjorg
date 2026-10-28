using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Passkeys;

/// <summary>
///     Completes a passkey registration, bound to the account completing it, and answers the new passkey's rename
///     page (a soft navigation; nothing here writes a cookie). In order: the cap (<see cref="PasskeyCap.Reached" />,
///     before any attestation), the attestation (every refusal one <see cref="ErrorCategory.Validation" />), the binding
///     -- the ceremony's user entity must be the caller, or <see cref="ErrorCategory.Forbidden" /> with nothing
///     persisted -- and only then the save, whose failure passes through.
/// </summary>
/// <remarks>
///     Review Focus 2: B posting a ceremony started for A is refused by the binding. A replayed attestation is
///     refused by the handler itself, which answers an already-registered credential as a failure (decompiled RC3),
///     so it never reaches the save.
/// </remarks>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="userManager">Counts the caller's passkeys, names the caller, and saves the passkey.</param>
/// <param name="signInManager">Runs the ceremony's second half.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
sealed class AddPasskeyHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	SignInManager<NorseUser> signInManager,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<AddPasskeyCommand, NavigationResult>
{
	static readonly Failed _anotherAccount = new(Problem.ModelError(ErrorCategory.Forbidden,
		"This passkey was created for a different account."));

	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(AddPasskeyCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> success);
		var user = success.Value;

		if (await PasskeyCap.IsReachedAsync(userManager, user).ConfigureAwait(false))
			return new(PasskeyCap.Reached);

		var attested = await signInManager.Outcome
			.PerformPasskeyAttestationAsync(request.Request.CredentialJson, request.Request.AttestationState,
				cancellationToken)
			.ConfigureAwait(false);
		if (attested.TryGetValue(out Failed attestationFailed))
			return new(attestationFailed);
		attested.TryGetValue(out Success<PasskeyAttestationResult> result);

		if (!string.Equals(result.Value.UserEntity!.Id, await userManager.GetUserIdAsync(user).ConfigureAwait(false),
				StringComparison.Ordinal))
			return new(_anotherAccount);

		var saved = await userManager.Outcome.AddOrUpdatePasskeyAsync(user, result.Value.Passkey!, cancellationToken)
			.ConfigureAwait(false);
		if (saved.TryGetValue(out Failed saveFailed))
			return new(saveFailed);

		return Outcome<NavigationResult>.Ok(new NavigationResult
		{
			NextUrl = CredentialIds.RenameUrl(httpContextAccessor.HttpContext!.Request.PathBase,
				CredentialIds.Encode(result.Value.Passkey!.CredentialId))
		});
	}
}
