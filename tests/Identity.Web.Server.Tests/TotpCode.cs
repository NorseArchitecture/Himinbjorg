using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>The authenticator app's side of RFC 6238, for facts that enroll a real key and then answer it.</summary>
static class TotpCode
{
	/// <summary>The code the authenticator app would show now, from the stored base32 key.</summary>
	/// <param name="key">The base32 authenticator key, as the store holds it.</param>
	[SuppressMessage("Security", "CA5350", Justification = "RFC 6238 TOTP is HMAC-SHA1 by definition, as authenticator apps compute it.")]
	public static string Now(string key)
	{
		var secret = Base32Decode(key);
		Span<byte> step = stackalloc byte[8];
		BinaryPrimitives.WriteInt64BigEndian(step, DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30);
		var hash = HMACSHA1.HashData(secret, step);
		var offset = hash[^1] & 0x0F;
		var binary = BinaryPrimitives.ReadInt32BigEndian(hash.AsSpan(offset, 4)) & 0x7FFFFFFF;
		return (binary % 1_000_000).ToString("D6", CultureInfo.InvariantCulture);
	}

	static byte[] Base32Decode(string key)
	{
		const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
		List<byte> bytes = [];
		int buffer = 0, bits = 0;
		foreach (var c in key.TrimEnd('=').ToUpperInvariant())
		{
			buffer = ((buffer << 5) | Alphabet.IndexOf(c, StringComparison.Ordinal)) & 0xFFFF;
			bits += 5;
			if (bits < 8)
				continue;
			bits -= 8;
			bytes.Add((byte)(buffer >> bits));
		}

		return [.. bytes];
	}
}
