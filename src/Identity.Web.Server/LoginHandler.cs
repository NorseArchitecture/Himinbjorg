using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Primitives;
using Norse.Primitives.Pii;

namespace Norse.Identity.Web.Server;

sealed class LoginHandler(
	SignInManager<NorseUser> signInManager,
	DeferredCompletion deferredCompletion,
	IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<LoginCommand, NavigationResult>
{
	// Heimdall serves the 2FA challenge page (AuthN.Components.FluentUI/LoginWith2fa.razor,
	// @page "/Account/LoginWith2fa"); Himinbjörg is the layer that mints the challenge, so it is also the
	// layer that resolves NavigationResult.NextUrl down to a concrete value in every case -- every client
	// (Blazor Server, WASM, MAUI) just navigates to it, with no route knowledge or default of its own.
	//
	// Root-relative, not path-relative, and combined with the live request's PathBase via
	// UriHelper.BuildRelative at the use site (matching IdentityComponentsEndpointRouteBuilderExtensions'
	// own PathBase-preserving pattern), like every other NextUrl this handler resolves: a genuine
	// origin-absolute URL that resolves identically wherever the client navigates from, correct under a
	// non-root PathBase too -- BuildRelative is a no-op prefix when PathBase is empty.
	const string TwoFactorChallengeRoute = "/Account/LoginWith2fa";

	// Anti-enumeration as a reference-identity guarantee (spec §9.3), not a structural coincidence:
	// Problem.Errors is a dictionary, so two separately built Problems carrying identical content
	// still compare unequal as records. Every credential-failure path below returns this exact
	// instance, so the collapse is provable by reference, not just by matching field values.
	static readonly Failed _invalidCredentials =
		new(Problem.ModelError(ErrorCategory.InvalidCredentials, "Invalid email or password."));

	// Read once per Handle call -- HttpContext.Request.PathBase reflects the live request the sender
	// is dispatching for, empty ("") for today's root-hosted deployment, and BuildRelative treats an
	// empty PathBase as a no-op prefix, so every NextUrl value stays byte-identical to before this
	// property existed until a non-root PathBase is actually in play.
	PathString PathBase =>
		httpContextAccessor.HttpContext!.Request.PathBase;

	public async ValueTask<Outcome<NavigationResult>> Handle(LoginCommand request,
		CancellationToken cancellationToken = default)
	{
		var wire = request.Request;

		// The server-side validator run guarantees a proven stamp before this handler executes; a
		// stamp that is somehow not a success (hostile caller, validator misregistration) is
		// indistinguishable from bad credentials on purpose — same anti-enumeration collapse.
		if (!wire.Email.TryGetValue(out Success<EmailAddress> email))
			return new Outcome<NavigationResult>(_invalidCredentials);

		// SignInManager mints/clears the cookie itself via its own IHttpContextAccessor dependency —
		// no manual HttpContext.SignInAsync call needed here (must register AddHttpContextAccessor()).
		// WireValue is the deliberate plaintext egress — Identity's store speaks canonical strings.
		// The .Outcome view maps the SignInResult (spec §4.12); this handler only routes and words it.
		var outcome = await signInManager.Outcome.PasswordSignInAsync(
				email.Value.WireValue, wire.Password, wire.RememberMe, lockoutOnFailure: true, cancellationToken)
			.ConfigureAwait(false);
		if (outcome.TryGetValue(out Failed failed))
			return SignInRefusal.Collapse(failed, _invalidCredentials);

		// The user proved they know the correct password -- this is NOT a credential failure, so it
		// must never fall into the shared _invalidCredentials collapse (SignInRefusal) (that would make a correct
		// password indistinguishable from a wrong one to a 2FA-enabled user). It rides the success
		// side of the Outcome instead, distinguished from a completed login by NextUrl pointing at the
		// 2FA challenge rather than a bare flag. NorseSignInManager writes no partial two-factor cookie
		// (nor defers one): it parks a protected challenge token on HttpContext.Items, which carries the
		// user, the stamp, and the caller's RememberMe choice, so the URL carries only that token -- and
		// with nothing stashed there is no deferred-completion detour on this branch.
		if (outcome.TryGetValue(out Success<SignInCompletion> completion)
			&& completion.Value is SignInCompletion.RequiresTwoFactor)
		{
			var token = httpContextAccessor.HttpContext!.Items[NorseSignInManager.TwoFactorChallengeItemName] as string
				?? throw new InvalidOperationException("RequiresTwoFactor without a parked challenge");
			return Outcome<NavigationResult>.Ok(new NavigationResult
			{
				NextUrl = UriHelper.BuildRelative(PathBase, TwoFactorChallengeRoute,
					QueryString.Create("challenge", token))
			});
		}

		// The app root, PathBase-qualified, is the concrete default for a completed sign-in whose
		// cookie was written directly -- resolved here, not left for the client to supply, so NextUrl
		// is never null.
		var appRoot = UriHelper.BuildRelative(PathBase, "/");
		return Outcome<NavigationResult>.Ok(new NavigationResult
		{
			NextUrl = deferredCompletion.TryBuildUrl(appRoot) ?? appRoot
		});
	}
}
