using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components;

namespace Norse.Identity.Web.Server;

sealed class LoginHandler(SignInManager<NorseUser> signInManager, LoginRequestValidator validator)
	: IRequestHandler<LoginRequest, Outcome<BoolResponse>>
{
	public async ValueTask<Outcome<BoolResponse>> Handle(LoginRequest request, CancellationToken cancellationToken)
	{
		var validation = await validator.ValidateAsync(request, cancellationToken).ConfigureAwait(false);
		if (!validation.IsValid)
			return Outcome<BoolResponse>.Err(ErrorCategory.Validation, (IReadOnlyDictionary<string, string[]>)validation.ToDictionary());

		// SignInManager mints/clears the cookie itself via its own IHttpContextAccessor dependency —
		// no manual HttpContext.SignInAsync call needed here (must register AddHttpContextAccessor()).
		var result = await signInManager.PasswordSignInAsync(
			request.Email, request.Password, request.RememberMe, lockoutOnFailure: true).ConfigureAwait(false);

		// A distinguishable category alone isn't enough — the UI (Task 8) reads only Errors, never
		// ErrorCategory (that's server-only), so the actual human-readable text has to be populated
		// here or LockedOut/NotAllowed would render identically to the deliberately-generic
		// credential-check failure above, defeating the reason they stayed distinguishable at all
		// (spec §9.3: "so they don't try 10000 times").
		if (result.IsLockedOut)
			return Outcome<BoolResponse>.Err(ErrorCategory.LockedOut,
				new Dictionary<string, string[]> { [""] = ["This account is locked out. Try again later or reset your password."] });
		if (result.IsNotAllowed)
			return Outcome<BoolResponse>.Err(ErrorCategory.NotAllowed,
				new Dictionary<string, string[]> { [""] = ["Sign-in is not allowed for this account."] });

		// Succeeded=false covers "no such user" and "wrong password" identically — deliberate,
		// anti-enumeration, see spec §9.3. Never Outcome.Err(InvalidCredentials).
		return Outcome<BoolResponse>.Ok(new BoolResponse { Value = result.Succeeded });
	}
}
