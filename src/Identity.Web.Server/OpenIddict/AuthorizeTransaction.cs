using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Primitives;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     The canonical authorize transaction (2026-10-29 OpenIddict spec §5.2, T4-10): every authorize parameter except
///     <c>norse_reauth</c>, hashed so that any changed parameter voids a marker. Structurally framed, so no two distinct
///     parameter sets serialize alike: the parameter count, then each name in ordinal order as a name tag, the
///     length-prefixed UTF-8 name and the value count, then each value, in received order, as a value tag and the
///     length-prefixed UTF-8 value. Integers are fixed-width little-endian <see cref="int" />. The method never takes
///     part (T4-7). A repeated value is hashed as received, never resolved: OpenIddict reads a repeated singular parameter
///     as absent rather than refusing it, so the authorize endpoint itself refuses one (or a case variant of one) before
///     any marker is minted (<c>OpenIddictAuthorizeEndpoint.IsAmbiguous</c>, spec §13.5).
/// </summary>
static class AuthorizeTransaction
{
	/// <summary>The one parameter the hash never covers: the marker the hash is carried in.</summary>
	public const string MarkerParameter = "norse_reauth";

	const byte NameTag = 0x01;
	const byte ValueTag = 0x02;

	// Strict: a lone surrogate throws rather than collapsing onto U+FFFD beside a genuine one. A parsed request never
	// carries one (its decoder already substitutes), so only a caller's own string could.
	static readonly UTF8Encoding _utf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

	/// <summary>The SHA-256 of the canonical transaction over <paramref name="parameters" />.</summary>
	/// <param name="parameters">The request's parameters, names exactly as received (ordinal; never case-folded).</param>
	/// <returns>The 32-byte hash.</returns>
	/// <exception cref="EncoderFallbackException">A name or value is not well-formed UTF-16.</exception>
	public static byte[] Hash(IEnumerable<KeyValuePair<string, StringValues>> parameters)
	{
		List<KeyValuePair<string, StringValues>> canonical =
		[
			.. parameters
				.Where(static parameter => !string.Equals(parameter.Key, MarkerParameter, StringComparison.Ordinal))
				.OrderBy(static parameter => parameter.Key, StringComparer.Ordinal)
		];

		using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
		AppendInt32(hash, canonical.Count);
		foreach (var (name, values) in canonical)
		{
			AppendTagged(hash, NameTag, name);
			AppendInt32(hash, values.Count);
			// A null value cannot arrive from a parsed request; it frames as the empty string.
			foreach (var value in values)
				AppendTagged(hash, ValueTag, value ?? string.Empty);
		}

		return hash.GetHashAndReset();
	}

	static void AppendTagged(IncrementalHash hash, byte tag, string text)
	{
		hash.AppendData([tag]);
		var bytes = _utf8.GetBytes(text);
		AppendInt32(hash, bytes.Length);
		hash.AppendData(bytes);
	}

	static void AppendInt32(IncrementalHash hash, int value)
	{
		Span<byte> bytes = stackalloc byte[sizeof(int)];
		BinaryPrimitives.WriteInt32LittleEndian(bytes, value);
		hash.AppendData(bytes);
	}
}
