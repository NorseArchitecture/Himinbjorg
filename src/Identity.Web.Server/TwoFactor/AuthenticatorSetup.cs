using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using QRCoder;

namespace Norse.Identity.Web.Server.TwoFactor;

/// <summary>
///     What the authenticator setup page shows, in the stock page's parity format: the key for manual entry, the
///     <c>otpauth://</c> URI an app scans, and that URI as a QR code rendered server side.
/// </summary>
static class AuthenticatorSetup
{
	/// <summary>The parity URI format: issuer, account, secret, issuer again.</summary>
	static readonly CompositeFormat _uriFormat =
		CompositeFormat.Parse("otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6");

	/// <summary>How many pixels each QR module spans; the client scales the image, so this only sets the viewBox.</summary>
	const int PixelsPerModule = 4;

	/// <summary>The key in lowercase groups of four, for manual entry.</summary>
	/// <param name="unformattedKey">The stored base32 key.</param>
	public static string FormatKey(string unformattedKey) =>
		string.Join(' ', unformattedKey.Chunk(4).Select(static group => new string(group))).ToLowerInvariant();

	/// <summary>The <c>otpauth://</c> URI, with the issuer and the account URL-encoded.</summary>
	/// <param name="issuer">The configured issuer.</param>
	/// <param name="email">The account's email, which is its username.</param>
	/// <param name="unformattedKey">The stored base32 key.</param>
	public static string Uri(string issuer, string email, string unformattedKey) =>
		string.Format(CultureInfo.InvariantCulture, _uriFormat, UrlEncoder.Default.Encode(issuer), UrlEncoder.Default.Encode(email),
			unformattedKey);

	/// <summary>
	///     <paramref name="uri" /> as an SVG QR code at error-correction level Q. The client shows it as an image, never
	///     as markup, and the document carries no script.
	/// </summary>
	/// <param name="uri">The <c>otpauth://</c> URI.</param>
	public static string QrSvg(string uri)
	{
		using QRCodeGenerator generator = new();
		using var data = generator.CreateQrCode(Encoding.UTF8.GetBytes(uri), QRCodeGenerator.ECCLevel.Q);
		using SvgQRCode svg = new(data);
		return svg.GetGraphic(PixelsPerModule);
	}
}
