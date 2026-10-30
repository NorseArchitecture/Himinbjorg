namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>How an <see cref="IGrantTermination.EndAsync" /> came out (2026-10-29 OpenIddict spec §5.5, <c>EndGrant</c>).</summary>
enum GrantEnd
{
	/// <summary>Not an outcome.</summary>
	None = 0,

	/// <summary>The authorization is durably <c>revoked</c>: a definite success on some attempt.</summary>
	Confirmed = 1,

	/// <summary>Every attempt failed or was indeterminate; the grant end is surfaced, never reported as confirmed.</summary>
	Unconfirmed = 2
}
