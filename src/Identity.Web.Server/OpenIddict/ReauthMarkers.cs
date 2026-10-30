using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     Protects and reads the <c>norse_reauth</c> marker (2026-10-29 OpenIddict spec §5.2): data-protected under its own
///     <see cref="Purpose" />, base64url so it rides a query string unescaped, and valid for <see cref="Lifetime" />. The
///     expiry travels inside the payload and is judged against the injected clock, never the protector's own. Burning a
///     marker once is the authorize endpoint's, in the one-shot ledger; this type only proves it genuine and unexpired.
///     One singleton serves the stamp point and the endpoint. Public only because the public
///     <see cref="NorseSignInManager" /> takes it by injection; every member that reads or writes a marker stays internal.
/// </summary>
/// <param name="dataProtectionProvider">The application's key ring.</param>
/// <param name="timeProvider">The clock expiry is judged by.</param>
public sealed class ReauthMarkers(IDataProtectionProvider dataProtectionProvider, TimeProvider timeProvider)
{
	/// <summary>The data-protection purpose; a value protected under any other purpose never reads as a marker.</summary>
	public const string Purpose = "Norse.Identity.ReauthMarker.v1";

	/// <summary>How long a marker is valid from its mint.</summary>
	public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

	// version (1) | marker id (16) | has user (1) | user id (16) | expires, UTC ticks (8) | hash length (4) | hash
	const byte Version = 1;
	const int GuidLength = 16;
	const int HeaderLength = 1 + GuidLength + 1 + GuidLength + sizeof(long) + sizeof(int);

	readonly IDataProtector _protector = dataProtectionProvider.CreateProtector(Purpose);

	/// <summary>Protects <paramref name="marker" />, its expiry included, for the authorize request's query string.</summary>
	/// <param name="marker">The marker.</param>
	/// <returns>The protected marker, base64url.</returns>
	internal string Protect(ReauthMarker marker)
	{
		ArgumentNullException.ThrowIfNull(marker);
		var payload = new byte[HeaderLength + marker.TransactionHash.Length];
		var span = payload.AsSpan();
		span[0] = Version;
		marker.MarkerId.TryWriteBytes(span.Slice(1, GuidLength));
		if (marker.UserId is { } userId)
		{
			span[1 + GuidLength] = 1;
			userId.TryWriteBytes(span.Slice(2 + GuidLength, GuidLength));
		}

		BinaryPrimitives.WriteInt64LittleEndian(span.Slice(2 + (2 * GuidLength), sizeof(long)), marker.ExpiresAt.UtcTicks);
		BinaryPrimitives.WriteInt32LittleEndian(span.Slice(HeaderLength - sizeof(int), sizeof(int)),
			marker.TransactionHash.Length);
		marker.TransactionHash.CopyTo(span[HeaderLength..]);
		return WebEncoders.Base64UrlEncode(_protector.Protect(payload));
	}

	/// <summary>
	///     Reads a protected marker. Anything malformed, tampered with, protected under another purpose or key ring, or
	///     expired (its expiry at or before now) answers <see langword="false" />, never throws.
	/// </summary>
	/// <param name="protectedMarker">The value <see cref="Protect" /> produced.</param>
	/// <param name="marker">The marker, when genuine and unexpired.</param>
	/// <returns>Whether the marker is genuine and unexpired.</returns>
	internal bool TryUnprotect(string protectedMarker, [NotNullWhen(true)] out ReauthMarker? marker)
	{
		marker = null;
		if (string.IsNullOrEmpty(protectedMarker))
			return false;

		byte[] payload;
		try
		{
			payload = _protector.Unprotect(WebEncoders.Base64UrlDecode(protectedMarker));
		}
		// FormatException: the base64url decode that precedes the protector refuses a malformed value.
		catch (Exception exception) when (exception is CryptographicException or FormatException)
		{
			return false;
		}

		var span = payload.AsSpan();
		if (span.Length < HeaderLength || span[0] != Version || span[1 + GuidLength] > 1
			|| BinaryPrimitives.ReadInt32LittleEndian(span.Slice(HeaderLength - sizeof(int), sizeof(int)))
			!= span.Length - HeaderLength)
			return false;

		var ticks = BinaryPrimitives.ReadInt64LittleEndian(span.Slice(2 + (2 * GuidLength), sizeof(long)));
		if (ticks is < 0 || ticks > DateTimeOffset.MaxValue.UtcTicks)
			return false;
		DateTimeOffset expiresAt = new(ticks, TimeSpan.Zero);
		if (expiresAt <= timeProvider.GetUtcNow())
			return false;

		marker = new(
			new(span.Slice(1, GuidLength)),
			span[1 + GuidLength] == 1 ? new Guid(span.Slice(2 + GuidLength, GuidLength)) : null,
			span[HeaderLength..].ToArray(),
			expiresAt);
		return true;
	}

	/// <summary>
	///     Reads the marker a sign-in's landing carries: only when the landing's path is exactly the authorize endpoint
	///     under the live <paramref name="pathBase" /> (ordinal, nothing normalized), its query carries exactly one
	///     parameter named exactly <c>norse_reauth</c> (ordinal; a differently cased spelling is an unknown parameter, as
	///     <see cref="AuthorizeTransaction" /> treats it), and that value unprotects (<see cref="TryUnprotect" />).
	/// </summary>
	/// <param name="landing">The resolved landing of the credential sign-in in progress.</param>
	/// <param name="pathBase">The live request's <c>PathBase</c>.</param>
	/// <param name="marker">The marker, when the landing carries a genuine, unexpired one.</param>
	/// <returns>Whether the landing carries a genuine, unexpired marker.</returns>
	internal bool TryReadFromLanding(string landing, PathString pathBase,
		[NotNullWhen(true)] out ReauthMarker? marker)
	{
		marker = null;
		if (string.IsNullOrEmpty(landing))
			return false;

		// The query ends at the first #; the path at the first ? or # (ReturnUrls' own split).
		var fragment = landing.IndexOf('#', StringComparison.Ordinal);
		var beforeFragment = fragment < 0 ?
			landing :
			landing[..fragment];
		var query = beforeFragment.IndexOf('?', StringComparison.Ordinal);
		var path = query < 0 ?
			beforeFragment :
			beforeFragment[..query];
		if (query < 0 || !string.Equals(path, pathBase.Add(AuthorizePath).Value, StringComparison.Ordinal))
			return false;

		return TryReadMarkerParameter(beforeFragment[query..], out var value) && TryUnprotect(value, out marker);
	}

	// Ordinal, as AuthorizeTransaction excludes the marker: QueryHelpers.ParseQuery folds case, so NORSE_REAUTH would read
	// as the marker here while taking part in the hash as an unknown parameter. A differently cased spelling is skipped;
	// two exact ones are ambiguous and read as none, failing closed.
	static bool TryReadMarkerParameter(string query, [NotNullWhen(true)] out string? value)
	{
		value = null;
		foreach (var pair in new QueryStringEnumerable(query))
		{
			if (!string.Equals(pair.DecodeName().ToString(), AuthorizeTransaction.MarkerParameter, StringComparison.Ordinal))
				continue;
			if (value is not null)
			{
				value = null;
				return false;
			}

			value = pair.DecodeValue().ToString();
		}

		return !string.IsNullOrEmpty(value);
	}

	/// <summary>The authorize endpoint's path, below <c>PathBase</c>.</summary>
	internal static readonly PathString AuthorizePath = new("/connect/authorize");
}
