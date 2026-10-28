namespace Norse.Identity.Web.Server.Tests.ExternalLogin;

/// <summary>
///     Id token payloads whose claim names a case-insensitive claim lookup would confuse with the email or its verified
///     flag, each with whether the token vouches for exactly one email. <see cref="Vouched" /> stands for the token's
///     own email and <see cref="Victim" /> for an address a forged claim names; <see cref="Fill" /> substitutes both.
/// </summary>
static class IdTokenVariants
{
	/// <summary>The token's own <c>email</c>.</summary>
	public const string Vouched = "$VOUCHED";

	/// <summary>The address a claim spelled like an email names.</summary>
	public const string Victim = "$VICTIM";

	/// <summary>The payloads, each with whether the token vouches for <see cref="Vouched" />.</summary>
	public static TheoryData<string, bool> Payloads =>
		new()
		{
			{ """{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/EMAILADDRESS":"$VICTIM","email":"$VOUCHED","email_verified":true}""", true },
			{ """{"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":"$VICTIM","email":"$VOUCHED","email_verified":true}""", true },
			{ """{"Email":"$VICTIM","email":"$VOUCHED","email_verified":true}""", true },
			{ """{"Norse.Identity.VerifiedEmail":"$VICTIM","email":"$VOUCHED","email_verified":true}""", true },
			{ """{"email":"$VOUCHED","email_verified":"TRUE"}""", true },
			{ """{"norse.identity.emailverified":"true","email":"$VOUCHED"}""", false },
			{ """{"NORSE.IDENTITY.EMAILVERIFIED":"true","email":"$VOUCHED"}""", false },
			{ """{"Email_Verified":true,"email":"$VOUCHED"}""", false },
			{ """{"email":["$VICTIM","$VOUCHED"],"email_verified":true}""", false },
			{ """{"email":"$VOUCHED","email_verified":[true,true]}""", false },
			{ """{"email":{"address":"$VICTIM"},"email_verified":true}""", false },
			{ """{"email":"$VOUCHED","email_verified":"false"}""", false },
			{ """{"email":"$VOUCHED","email_verified":"yes"}""", false },
			{ """{"email":"","email_verified":true}""", false }
		};

	/// <summary>
	///     Claim names a case-insensitive lookup reads as <see cref="System.Security.Claims.ClaimTypes.NameIdentifier" />,
	///     which RC3's <c>GetExternalLoginInfoAsync</c> takes as the provider key ahead of <c>sub</c>.
	/// </summary>
	public static TheoryData<string> ForgedNameIdentifiers =>
		new()
		{
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
			"HTTP://SCHEMAS.XMLSOAP.ORG/WS/2005/05/IDENTITY/CLAIMS/NAMEIDENTIFIER",
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/NameIdentifier"
		};

	/// <summary>Prefixes a payload's members with the token's <c>sub</c>.</summary>
	public static string WithSubject(string payload, string subject) =>
		payload.Length > 2 ?
			$$"""{"sub":"{{subject}}",{{payload[1..]}}""" :
			$$"""{"sub":"{{subject}}"}""";

	/// <summary>Substitutes the two addresses into a payload.</summary>
	public static string Fill(string payload, string vouched, string victim) =>
		payload.Replace(Vouched, vouched, StringComparison.Ordinal).Replace(Victim, victim, StringComparison.Ordinal);
}
