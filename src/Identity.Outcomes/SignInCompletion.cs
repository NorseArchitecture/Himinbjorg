namespace Norse.Identity.Outcomes;

/// <summary>How a successful sign-in answer completes; failures travel as an <c>Outcome</c> failure instead.</summary>
public enum SignInCompletion
{
	/// <summary>Never a valid completion.</summary>
	Unspecified = 0,

	/// <summary>The user is signed in.</summary>
	SignedIn = 1,

	/// <summary>The password was right; a second factor is still required.</summary>
	RequiresTwoFactor = 2
}
