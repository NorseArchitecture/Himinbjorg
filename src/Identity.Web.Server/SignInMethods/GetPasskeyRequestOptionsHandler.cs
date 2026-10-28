using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.SignInMethods;

/// <summary>
///     Begins a passkey sign-in: the WebAuthn request options for no particular user, and the protected, one-shot
///     assertion state the client echoes back on <see cref="PasskeySignInHandler" />. In place; nothing is stored.
/// </summary>
/// <param name="signInManager">Runs the ceremony through its <c>.Outcome</c> view.</param>
sealed class GetPasskeyRequestOptionsHandler(SignInManager<NorseUser> signInManager)
	: IRequestHandler<GetPasskeyRequestOptionsCommand, PasskeyRequestOptionsResponse>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<PasskeyRequestOptionsResponse>> Handle(GetPasskeyRequestOptionsCommand request,
		CancellationToken cancellationToken = default)
	{
		var outcome = await signInManager.Outcome.MakePasskeyRequestOptionsAsync(cancellationToken).ConfigureAwait(false);
		if (outcome.TryGetValue(out Failed failed))
			return new(failed);
		outcome.TryGetValue(out Success<PasskeyCeremony> ceremony);
		return Outcome<PasskeyRequestOptionsResponse>.Ok(new PasskeyRequestOptionsResponse
		{
			OptionsJson = ceremony.Value.OptionsJson,
			AssertionState = ceremony.Value.State
		});
	}
}
