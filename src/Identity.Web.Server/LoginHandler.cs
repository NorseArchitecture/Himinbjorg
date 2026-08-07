using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server;

sealed class LoginHandler(SignInManager<NorseUser> signInManager, IDeferredSignIn deferredSignIn, IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<LoginCommand, LoginResult>
{
	// Anti-enumeration as a reference-identity guarantee (spec §9.3), not a structural coincidence:
	// Problem.Errors is a dictionary, so two separately built Problems carrying identical content
	// still compare unequal as records. Every credential-failure path below returns this exact
	// instance, so the collapse is provable by reference, not just by matching field values.
	static readonly Failed _invalidCredentials =
		new(Problem.ModelError(ErrorCategory.InvalidCredentials, "Invalid email or password."));

	// Himinbjörg is the layer that owns and serves the 2FA challenge page (still the pre-migration
	// scaffold at Components/Pages/LoginWith2fa.razor, @page "/Account/LoginWith2fa"), so it's also the
	// layer that resolves LoginResult.NextUrl down to a concrete value in every case -- every client
	// (Blazor Server, WASM, MAUI) just navigates to it, with no route knowledge or default of its own.
	const string TwoFactorChallengeRoute = "Account/LoginWith2fa";

	public async ValueTask<Outcome<LoginResult>> Handle(LoginCommand request, CancellationToken cancellationToken = default)
	{
		var wire = request.Request;

		// SignInManager mints/clears the cookie itself via its own IHttpContextAccessor dependency —
		// no manual HttpContext.SignInAsync call needed here (must register AddHttpContextAccessor()).
		var result = await signInManager.PasswordSignInAsync(
			wire.Email, wire.Password, wire.RememberMe, lockoutOnFailure: true).ConfigureAwait(false);

		// A distinguishable category alone isn't enough — the UI (Task 8) reads only Errors, never
		// ErrorCategory (that's server-only), so the actual human-readable text has to be populated
		// here or LockedOut/NotAllowed would render identically to the deliberately-generic
		// credential-check failure below, defeating the reason they stayed distinguishable at all
		// (spec §9.3: "so they don't try 10000 times").
		if (result.IsLockedOut)
			return Outcome<LoginResult>.Err(ErrorCategory.LockedOut,
				new Dictionary<string, string[]> { [""] = ["This account is locked out. Try again later or reset your password."] });
		if (result.IsNotAllowed)
			return Outcome<LoginResult>.Err(ErrorCategory.NotAllowed,
				new Dictionary<string, string[]> { [""] = ["Sign-in is not allowed for this account."] });

		// The user proved they know the correct password -- this is NOT a credential failure, so it
		// must never fall into the shared _invalidCredentials branch below (that would make a correct
		// password indistinguishable from a wrong one to a 2FA-enabled user). It rides the success
		// side of the Outcome instead, distinguished from a completed login by NextUrl pointing at the
		// 2FA challenge -- RememberMe included, so the client never has to reconstruct it from its own
		// request state -- rather than a bare flag. On an established circuit, NorseSignInManager
		// already deferred the partial two-factor cookie the same way it defers a full sign-in
		// (SignInOrTwoFactorAsync override) -- TryGetDeferredCompletionUrl finds that same stash and
		// routes through the real completion request instead of the challenge page directly, exactly
		// like the completed-sign-in branch below does.
		if (result.RequiresTwoFactor)
		{
			var challengeUrl = $"{TwoFactorChallengeRoute}?RememberMe={(wire.RememberMe ? "true" : "false")}";
			return Outcome<LoginResult>.Ok(new LoginResult { NextUrl = TryGetDeferredCompletionUrl(challengeUrl) ?? challengeUrl });
		}

		// PasswordSignInAsync already collapses "no such user" and "wrong password" into the single
		// SignInResult.Failed case — anti-enumeration, spec §9.3 — so there is exactly one
		// credential-failure branch here, and it always returns the shared _invalidCredentials
		// instance rather than minting a fresh Problem per call.
		if (!result.Succeeded)
			return new Outcome<LoginResult>(_invalidCredentials);

		// "/" is the concrete default for a completed sign-in whose cookie was written directly --
		// resolved here, not left for the client to supply, so NextUrl is never null.
		return Outcome<LoginResult>.Ok(new LoginResult { NextUrl = TryGetDeferredCompletionUrl("/") ?? "/" });
	}

	// NOT verbatim-duplicated in LogoutHandler anymore -- Logout only ever lands back on "/", so its
	// copy keeps a bare, parameterless shape; this one needs a returnUrl parameter because Login has
	// two distinct destinations (a completed sign-in vs. the 2FA challenge) that can each need the
	// deferred-completion detour.
	string? TryGetDeferredCompletionUrl(string returnUrl)
	{
		// Only ever set on the Blazor-Server in-process path (a circuit that couldn't Set-Cookie
		// because the response had already started) — a real gRPC/WASM call never stashes this, so
		// this naturally returns null there without any channel-specific branching.
		if (httpContextAccessor.HttpContext!.Items[NorseSignInManager.DeferredSignInKeyItemName] is not string key)
			return null;

		return deferredSignIn.BuildCompletionUrl(key, returnUrl);
	}
}
