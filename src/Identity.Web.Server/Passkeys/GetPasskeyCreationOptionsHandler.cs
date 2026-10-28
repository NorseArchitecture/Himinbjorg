using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Passkeys;

/// <summary>
///     Begins a passkey registration in place: the WebAuthn creation options and the protected attestation state
///     <see cref="AddPasskeyHandler" /> takes back. Stateless on the server. A caller at the cap answers
///     <see cref="PasskeyCap.Reached" /> and no ceremony starts.
/// </summary>
/// <param name="caller">Resolves the calling user from the principal.</param>
/// <param name="userManager">Counts the caller's passkeys.</param>
/// <param name="signInManager">Runs the ceremony's first half.</param>
sealed class GetPasskeyCreationOptionsHandler(
	AccountCaller caller,
	UserManager<NorseUser> userManager,
	SignInManager<NorseUser> signInManager)
	: IRequestHandler<GetPasskeyCreationOptionsCommand, PasskeyCreationOptionsResponse>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<PasskeyCreationOptionsResponse>> Handle(GetPasskeyCreationOptionsCommand request,
		CancellationToken cancellationToken = default)
	{
		var found = await caller.ResolveAsync(cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> user);

		if (await PasskeyCap.IsReachedAsync(userManager, user.Value).ConfigureAwait(false))
			return new(PasskeyCap.Reached);

		var ceremony = await signInManager.Outcome.MakePasskeyCreationOptionsAsync(user.Value, cancellationToken)
			.ConfigureAwait(false);
		if (ceremony.TryGetValue(out Failed failed))
			return new(failed);
		ceremony.TryGetValue(out Success<PasskeyCeremony> started);
		return Outcome<PasskeyCreationOptionsResponse>.Ok(new PasskeyCreationOptionsResponse
		{
			OptionsJson = started.Value.OptionsJson,
			AttestationState = started.Value.State
		});
	}
}
