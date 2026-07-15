namespace Norse.Identity.Web.Server;

/// <summary>
/// Form-bound state for a passkey creation or request round-trip, posted back from the
/// <c>passkey-submit</c> custom element after the browser's WebAuthn ceremony completes.
/// </summary>
public class PasskeyInputModel
{
	/// <summary>The serialized WebAuthn credential returned by the browser, or <see langword="null" /> if the ceremony has not completed.</summary>
	public string? CredentialJson { get; set; }

	/// <summary>The error message reported by the browser's WebAuthn ceremony, or <see langword="null" /> if it succeeded.</summary>
	public string? Error { get; set; }
}
