using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace Norse.Identity.Web.Server;

/// <summary>
///     The emailed codes' wire form: an Identity token, UTF-8 encoded and then Base64Url encoded so it survives a URL.
///     Each handler answers a malformed code with its own static refusal instance, so the decode reports failure rather
///     than building one.
/// </summary>
static class IdentityTokens
{
	/// <summary>Base64Url-decodes an emailed <paramref name="code" /> back to the Identity token it carries.</summary>
	/// <param name="code">The Base64Url-encoded code from the link.</param>
	/// <param name="token">The decoded token, or <see cref="string.Empty" /> when the code is malformed.</param>
	/// <returns><see langword="true" /> when the code decoded; <see langword="false" /> when it is malformed.</returns>
	public static bool TryDecode(string code, out string token)
	{
		try
		{
			token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
			return true;
		}
		catch (FormatException)
		{
			token = string.Empty;
			return false;
		}
	}
}
