using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;

namespace Norse.Identity.Web.Server.TwoFactor;

/// <summary>
///     The one-shot recovery-codes handoff (T3-12): the codes an enable issues, sealed into the <c>NextUrl</c> so they
///     survive the forced reload the stamp rotation needs, and revealed once by <c>/Account/Manage/ShowRecoveryCodes</c>.
///     The payload is a <c>|</c>-delimited string -- no JSON here by NORSE070 -- under <see cref="Purpose" />, binding the
///     user and the security stamp read after the writes, so a later rotation refuses it.
/// </summary>
static class RecoveryCodesHandoff
{
	/// <summary>The data-protection purpose; a handoff protected under any other purpose is refused.</summary>
	public const string Purpose = "Norse.Identity.RecoveryCodesHandoff.v1";

	/// <summary>The page that reveals a handoff, root-relative.</summary>
	public const string Route = "/Account/Manage/ShowRecoveryCodes";

	/// <summary>How long a sealed handoff may be revealed.</summary>
	public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

	const string Version = "v1";
	const char Separator = '|';
	const char CodeSeparator = ';';
	const int FieldCount = 4;

	/// <summary>Seals <paramref name="codes" /> for <paramref name="userId" /> under <paramref name="securityStamp" />.</summary>
	/// <param name="protector">The time-limited protector under <see cref="Purpose" />.</param>
	/// <param name="userId">The user the codes belong to.</param>
	/// <param name="securityStamp">The user's security stamp, read after the writes.</param>
	/// <param name="codes">The recovery codes issued.</param>
	/// <returns>The opaque handoff, valid for <see cref="Lifetime" />.</returns>
	public static string Protect(ITimeLimitedDataProtector protector, string userId, string securityStamp, string[] codes) =>
		protector.Protect(string.Join(Separator, Version, userId, securityStamp, string.Join(CodeSeparator, codes)), Lifetime);

	/// <summary>
	///     Reads a handoff back. A handoff that is garbage, tampered with, expired, protected under another purpose, or
	///     of another version or shape answers <see langword="false" /> rather than throwing.
	/// </summary>
	/// <param name="protector">The time-limited protector under <see cref="Purpose" />.</param>
	/// <param name="handoff">The handoff the client handed back.</param>
	/// <param name="opened">What the handoff carried, when it is valid.</param>
	/// <returns><see langword="true" /> when <paramref name="opened" /> is valid.</returns>
	public static bool TryUnprotect(ITimeLimitedDataProtector protector, string handoff,
		[NotNullWhen(true)] out Opened? opened)
	{
		opened = null;
		byte[] payload;
		DateTimeOffset expiresAt;
		try
		{
			payload = protector.Unprotect(WebEncoders.Base64UrlDecode(handoff), out expiresAt);
		}
		// FormatException: the base64url decode refuses a malformed handoff.
		catch (Exception exception) when (exception is CryptographicException or FormatException)
		{
			return false;
		}

		if (Encoding.UTF8.GetString(payload).Split(Separator, FieldCount) is not [Version, { Length: > 0 } userId, { Length: > 0 } stamp, { Length: > 0 } codes])
			return false;

		opened = new(userId, stamp, codes.Split(CodeSeparator), payload, expiresAt);
		return true;
	}

	/// <summary>An unprotected handoff.</summary>
	/// <param name="UserId">The user the codes belong to.</param>
	/// <param name="SecurityStamp">The stamp the handoff was sealed under.</param>
	/// <param name="Codes">The recovery codes.</param>
	/// <param name="Payload">The raw unprotected payload, which the one-shot ledger consumes (P5).</param>
	/// <param name="ExpiresAt">The handoff's own expiry, which bounds the ledger's record of it.</param>
	public sealed record Opened(string UserId, string SecurityStamp, IReadOnlyList<string> Codes, ReadOnlyMemory<byte> Payload,
		DateTimeOffset ExpiresAt);
}
