using Norse.Abstractions.Contracts;

namespace Norse.Identity.Web.Server;

/// <summary>
///     The refusal fold every sign-in handler shares. A distinguishable category alone isn't enough: the UI reads only
///     <see cref="Problem.Errors" />, never <see cref="ErrorCategory" /> (that's server-only), so the human-readable
///     text is populated here or <see cref="ErrorCategory.LockedOut" />/<see cref="ErrorCategory.NotAllowed" /> would
///     render identically to the deliberately generic credential failure, defeating the reason they stayed
///     distinguishable at all (spec §9.3: "so they don't try 10000 times").
/// </summary>
static class SignInRefusal
{
	/// <summary>
	///     Folds a sign-in refusal: <see cref="ErrorCategory.LockedOut" /> and <see cref="ErrorCategory.NotAllowed" />
	///     carry their own text; every other failure -- wrong credentials, a stamp mismatch, an indeterminate
	///     access-failed increment (explicit-writes spec §4.5: sign-in fails closed), a key destroyed mid-erasure (an
	///     erased account must read as bad credentials) -- collapses onto <paramref name="fallback" />.
	/// </summary>
	/// <param name="failed">The refusal the sign-in view answered.</param>
	/// <param name="fallback">
	///     The caller's one static instance, so the anti-enumeration collapse is a reference-identity guarantee: a
	///     <see cref="Problem" />'s errors are a dictionary, so two separately built identical instances compare unequal.
	/// </param>
	/// <returns>The refusal to answer.</returns>
	public static Outcome<NavigationResult> Collapse(Failed failed, Failed fallback) => failed.Problem.Category switch
	{
		ErrorCategory.LockedOut => Outcome<NavigationResult>.Err(ErrorCategory.LockedOut,
			new Dictionary<string, string[]>
			{
				[""] = ["This account is locked out. Try again later or reset your password."]
			}),
		ErrorCategory.NotAllowed => Outcome<NavigationResult>.Err(ErrorCategory.NotAllowed,
			new Dictionary<string, string[]> { [""] = ["Sign-in is not allowed for this account."] }),
		_ => new Outcome<NavigationResult>(fallback)
	};
}
