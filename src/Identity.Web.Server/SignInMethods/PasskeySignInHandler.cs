using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.SignInMethods;

/// <summary>
///     Completes a passkey sign-in and answers the landing <see cref="ReturnUrls.Resolve" /> decided, through the
///     deferred-completion detour when a circuit stashed the cookie (a <c>ISessionTransition.Begin</c> continuation).
///     Every credential refusal -- a bad, expired, foreign-purpose or replayed state, a failed assertion, a failed
///     sign-count update, an erased subject -- collapses onto one static instance (<see cref="SignInRefusal" />); a
///     lockout and a not-allowed account keep their own text. A two-factor account signs in without the challenge (the
///     recorded <c>bypassTwoFactor: true</c>); the challenge branch stays for parity with <see cref="LoginHandler" />.
/// </summary>
/// <param name="signInManager">Runs the assertion through its <c>.Outcome</c> view.</param>
/// <param name="deferredCompletion">Builds the completion detour for whatever the sign-in stashed.</param>
/// <param name="httpContextAccessor">Reaches the live request, for the park and its <c>PathBase</c>.</param>
sealed class PasskeySignInHandler(
	SignInManager<NorseUser> signInManager,
	DeferredCompletion deferredCompletion,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<PasskeySignInCommand, NavigationResult>
{
	// LoginHandler's route: Heimdall serves the challenge page; this layer resolves the URL.
	const string TwoFactorChallengeRoute = "/Account/LoginWith2fa";

	// The anti-enumeration collapse as a reference-identity guarantee (spec §9.3), as LoginHandler's.
	static readonly Failed _invalidPasskey =
		new(Problem.ModelError(ErrorCategory.InvalidCredentials, "The passkey could not be used to sign in."));

	/// <inheritdoc />
	public async ValueTask<Outcome<NavigationResult>> Handle(PasskeySignInCommand request,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(request);
		var wire = request.Request;
		var httpContext = httpContextAccessor.HttpContext!;
		var pathBase = httpContext.Request.PathBase;
		var landing = ReturnUrls.Resolve(wire.ReturnUrl, pathBase);

		Outcome<SignInCompletion> outcome;
		using (ParkedReturnUrl.Park(httpContext, landing))
			outcome = await signInManager.Outcome.PasskeyAssertionSignInAsync(
					wire.CredentialJson, wire.AssertionState, wire.RememberMe, cancellationToken)
				.ConfigureAwait(false);
		if (outcome.TryGetValue(out Failed failed))
			return SignInRefusal.Collapse(failed, _invalidPasskey);

		if (outcome.TryGetValue(out Success<SignInCompletion> completion)
			&& completion.Value is SignInCompletion.RequiresTwoFactor)
		{
			var token = httpContext.Items[NorseSignInManager.TwoFactorChallengeItemName] as string
				?? throw new InvalidOperationException("RequiresTwoFactor without a parked challenge");
			return Outcome<NavigationResult>.Ok(new NavigationResult
			{
				NextUrl = UriHelper.BuildRelative(pathBase, TwoFactorChallengeRoute, QueryString.Create("challenge", token))
			});
		}

		return Outcome<NavigationResult>.Ok(new NavigationResult
		{
			NextUrl = deferredCompletion.TryBuildUrl(landing) ?? landing
		});
	}
}
