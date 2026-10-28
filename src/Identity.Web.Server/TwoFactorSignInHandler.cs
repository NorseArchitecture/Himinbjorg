using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.Identity.EntityFramework;
using Norse.Primitives;

namespace Norse.Identity.Web.Server;

/// <summary>
///     Completes a parked two-factor challenge with an authenticator code. Success lands on the challenge's landing,
///     re-resolved by <see cref="ReturnUrls.Resolve" />, through the deferred-completion detour when a circuit stashed
///     the sign-in; every refusal but lockout and not-allowed collapses onto this handler's one static instance.
/// </summary>
/// <param name="signInManager">Redeems the challenge; must be a <see cref="NorseSignInManager" />.</param>
/// <param name="deferredCompletion">Builds the completion detour for whatever this request stashed.</param>
/// <param name="httpContextAccessor">Reaches the live request's <c>PathBase</c>.</param>
sealed class TwoFactorSignInHandler(
	SignInManager<NorseUser> signInManager,
	DeferredCompletion deferredCompletion,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<TwoFactorSignInCommand, NavigationResult>
{
	// The form's own wording in-process; over gRPC the text is stripped and the form recasts it.
	static readonly Failed _invalidCode =
		new(Problem.ModelError(ErrorCategory.InvalidCredentials, "Invalid authenticator code."));

	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(TwoFactorSignInCommand request,
		CancellationToken cancellationToken = default)
	{
		var wire = request.Request;
		var outcome = await signInManager.Outcome
			.TwoFactorChallengeSignInAsync(wire.Challenge, wire.Code, wire.RememberMachine, cancellationToken)
			.ConfigureAwait(false);
		if (outcome.TryGetValue(out Failed failed))
			return SignInRefusal.Collapse(failed, _invalidCode);

		// The view answers the landing the challenge carried; only ReturnUrls.Resolve decides one, so it is re-resolved.
		outcome.TryGetValue(out Success<string> landed);
		var landing = ReturnUrls.Resolve(landed.Value, httpContextAccessor.HttpContext!.Request.PathBase);
		return Outcome<NavigationResult>.Ok(new NavigationResult
		{
			NextUrl = deferredCompletion.TryBuildUrl(landing) ?? landing
		});
	}
}
