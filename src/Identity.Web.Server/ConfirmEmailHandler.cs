using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;

namespace Norse.Identity.Web.Server;

/// <summary>
///     Confirms an account's email address with the emailed confirmation code. Every failure passes through unchanged:
///     an unknown user is <see cref="ErrorCategory.NotFound" />, an erased one <see cref="ErrorCategory.Erased" />, and a
///     rejected or malformed code <see cref="ErrorCategory.InvalidCredentials" />.
/// </summary>
/// <param name="userManager">Finds the account and confirms its email.</param>
sealed class ConfirmEmailHandler(UserManager<NorseUser> userManager)
	: IRequestHandler<ConfirmEmailCommand, BoolResponse>
{
	static readonly Failed _malformedCode =
		new(Problem.ModelError(ErrorCategory.InvalidCredentials, "The confirmation link is invalid or has expired."));

	/// <inheritdoc />
	public async ValueTask<Outcome<BoolResponse>> Handle(ConfirmEmailCommand request,
		CancellationToken cancellationToken = default)
	{
		var wire = request.Request;
		var found = await userManager.Outcome.FindByIdAsync(wire.UserId, cancellationToken).ConfigureAwait(false);
		if (found.TryGetValue(out Failed lookupFailed))
			return new(lookupFailed);
		found.TryGetValue(out Success<NorseUser> user);

		if (!IdentityTokens.TryDecode(wire.Code, out var token))
			return new(_malformedCode);

		var confirmed = await userManager.Outcome.ConfirmEmailAsync(user.Value, token, cancellationToken)
			.ConfigureAwait(false);
		return confirmed.TryGetValue(out Failed failed) ?
			new(failed) :
			Outcome<BoolResponse>.Ok(new BoolResponse { Value = true });
	}
}
