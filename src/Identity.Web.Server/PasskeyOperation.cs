namespace Norse.Identity.Web.Server;

/// <summary>The WebAuthn ceremony a <c>passkey-submit</c> element should perform.</summary>
public enum PasskeyOperation
{
	/// <summary>Register a new passkey for the current user.</summary>
	Create = 0,

	/// <summary>Authenticate using an existing passkey.</summary>
	Request = 1,
}
