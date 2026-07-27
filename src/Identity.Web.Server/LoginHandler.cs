using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server;

sealed class LoginHandler(SignInManager<NorseUser> signInManager, IDeferredSignIn deferredSignIn, IHttpContextAccessor httpContextAccessor)
	: IRequestHandler<LoginCommand, LoginResult>
{
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
		// credential-check failure above, defeating the reason they stayed distinguishable at all
		// (spec §9.3: "so they don't try 10000 times").
		if (result.IsLockedOut)
			return Outcome<LoginResult>.Err(ErrorCategory.LockedOut,
				new Dictionary<string, string[]> { [""] = ["This account is locked out. Try again later or reset your password."] });
		if (result.IsNotAllowed)
			return Outcome<LoginResult>.Err(ErrorCategory.NotAllowed,
				new Dictionary<string, string[]> { [""] = ["Sign-in is not allowed for this account."] });

		// Succeeded=false covers "no such user" and "wrong password" identically — deliberate,
		// anti-enumeration, see spec §9.3. Never Outcome.Err(InvalidCredentials).
		return Outcome<LoginResult>.Ok(new LoginResult { Succeeded = result.Succeeded, DeferredCompletionUrl = TryGetDeferredCompletionUrl() });
	}

	// Duplicated verbatim in LogoutHandler — Buvy's explicit call: no shared helper class for four
	// lines shared by exactly two handlers.
	string? TryGetDeferredCompletionUrl()
	{
		// Only ever set on the Blazor-Server in-process path (a circuit that couldn't Set-Cookie
		// because the response had already started) — a real gRPC/WASM call never stashes this, so
		// this naturally returns null there without any channel-specific branching.
		if (httpContextAccessor.HttpContext!.Items[NorseSignInManager.DeferredSignInKeyItemName] is not string key)
			return null;

		return deferredSignIn.BuildCompletionUrl(key, "/");
	}
}
