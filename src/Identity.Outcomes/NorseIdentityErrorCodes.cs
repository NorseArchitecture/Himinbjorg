namespace Norse.Identity.Outcomes;

/// <summary>
///     The <c>IdentityError.Code</c> values Norse mints beside <c>IdentityErrorDescriber</c>'s own. Each one has an
///     explicit row in <see cref="IdentityOutcomeMap" />, and a test pins that every constant here does.
/// </summary>
public static class NorseIdentityErrorCodes
{
	/// <summary>A refused <c>SetUserNameAsync</c>: the username is derived from the email (spec §3.1).</summary>
	public const string UserNameIsDerived = "UserNameIsDerived";

	/// <summary>
	///     A flush whose commit may or may not have taken effect, with no stamp marker to resolve it (spec §4.10).
	/// </summary>
	public const string IndeterminateOutcome = "IndeterminateOutcome";

	/// <summary>
	///     A passkey enrollment whose credential id is already registered to another user or under another public
	///     key (spec §4.6).
	/// </summary>
	public const string PasskeyAlreadyRegistered = "PasskeyAlreadyRegistered";

	/// <summary>
	///     A refused <c>RemoveLoginAsync</c>: removing the login would leave the user with neither a password nor an
	///     external login (spec §5.9).
	/// </summary>
	public const string LastSignInMethod = "LastSignInMethod";
}
