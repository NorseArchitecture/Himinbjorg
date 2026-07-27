namespace Norse.Identity.Web.Server;

/// <summary>The WebAuthn ceremony a <c>passkey-submit</c> element should perform.</summary>
public enum PasskeyOperation
{
	/// <summary>Sentinel CLR default — never a valid ceremony; the markup must name one.</summary>
	Unspecified = 0,

	/// <summary>Register a new passkey for the current user.</summary>
	Create = 1,

	/// <summary>Authenticate using an existing passkey.</summary>
	Request = 2
}
