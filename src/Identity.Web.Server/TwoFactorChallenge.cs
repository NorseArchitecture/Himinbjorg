using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;

namespace Norse.Identity.Web.Server;

/// <summary>
///     What a password or external-login step proves before the second factor is asked for, carried back to
///     the client as an opaque, time-limited, data-protected token instead of ASP.NET Core Identity's partial
///     two-factor-user-id cookie (<see cref="NorseSignInManager" /> never writes that cookie). The payload is
///     a <c>|</c>-delimited string -- no JSON here by NORSE070 -- under <see cref="Purpose" />, and it binds
///     the security stamp current at the first step so a stamp rotation in between refuses the challenge.
/// </summary>
/// <param name="UserId">The user the first step proved.</param>
/// <param name="SecurityStamp">The user's security stamp when the challenge was minted.</param>
/// <param name="IsPersistent">Whether the completed sign-in should persist, as the first step asked.</param>
/// <param name="LoginProvider">The external login provider that proved the first step, or <see langword="null" /> for a password.</param>
sealed record TwoFactorChallenge(string UserId, string SecurityStamp, bool IsPersistent, string? LoginProvider)
{
	/// <summary>The data-protection purpose; a token protected under any other purpose is refused.</summary>
	public const string Purpose = "Norse.Identity.TwoFactorChallenge.v1";

	/// <summary>How long a minted challenge may be redeemed.</summary>
	public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

	const string Version = "v1";
	const char Separator = '|';

	/// <summary>Mints the opaque token for this challenge, valid for <see cref="Lifetime" />.</summary>
	/// <param name="protector">The time-limited protector under <see cref="Purpose" />.</param>
	/// <returns>The token the client hands back to complete the second factor.</returns>
	public string Protect(ITimeLimitedDataProtector protector) =>
		protector.Protect(
			$"{Version}{Separator}{UserId}{Separator}{SecurityStamp}{Separator}{(IsPersistent ? "1" : "0")}{Separator}{LoginProvider}",
			Lifetime);

	/// <summary>
	///     Reads a token back. A token that is garbage, expired, protected under another purpose, or of
	///     another version or shape answers <see langword="false" /> rather than throwing.
	/// </summary>
	/// <param name="protector">The time-limited protector under <see cref="Purpose" />.</param>
	/// <param name="token">The token the client handed back.</param>
	/// <param name="challenge">The challenge the token carried, when it is valid.</param>
	/// <returns><see langword="true" /> when <paramref name="challenge" /> is valid.</returns>
	public static bool TryUnprotect(ITimeLimitedDataProtector protector, string token,
		[NotNullWhen(true)] out TwoFactorChallenge? challenge)
	{
		challenge = null;
		string payload;
		try
		{
			payload = protector.Unprotect(token, out _);
		}
		// FormatException: the base64url decode that precedes the protector refuses a malformed token.
		catch (Exception exception) when (exception is CryptographicException or FormatException)
		{
			return false;
		}

		if (payload.Split(Separator) is not [Version, var userId, var securityStamp, var isPersistent, var loginProvider])
			return false;

		challenge = new(userId, securityStamp, isPersistent == "1", loginProvider.Length == 0 ? null : loginProvider);
		return true;
	}
}
