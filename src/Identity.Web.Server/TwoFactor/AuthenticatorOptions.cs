using System.ComponentModel.DataAnnotations;

namespace Norse.Identity.Web.Server.TwoFactor;

/// <summary>
///     The authenticator setup's configuration, bound from <see cref="Section" /> and validated at startup (T3-27): the
///     issuer is required, with no code default, so a host that forgets it fails before its first request rather than
///     enrolling authenticators under a wrong label.
/// </summary>
sealed class AuthenticatorOptions
{
	/// <summary>The configuration section the options bind from.</summary>
	public const string Section = "Identity:Authenticator";

	/// <summary>
	///     The issuer an authenticator app files the account under. Only new enrollments read it: an existing
	///     enrollment keeps the label it was scanned with.
	/// </summary>
	[Required]
	[MinLength(1)]
	public required string Issuer { get; set; }
}
