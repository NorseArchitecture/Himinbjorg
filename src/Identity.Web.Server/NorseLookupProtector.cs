using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;

namespace Norse.Identity.Web.Server;

/// <summary>
/// ASP.NET Core Identity's <see cref="ILookupProtector"/> over the platform's rotatable lookup keyring:
/// a deterministic keyed HMAC-SHA256 blind index. Determinism is the entire point -- the same input
/// under the same key always yields the same output, so equality lookups
/// (<c>WHERE NormalizedEmail = @hash</c>) keep working without the plaintext ever touching the column.
/// </summary>
/// <param name="keyRing">The lookup-plane keyring.</param>
public sealed class NorseLookupProtector(ILookupKeyRing keyRing) : ILookupProtector
{
	/// <inheritdoc />
	public string? Protect(string keyId, string? data)
	{
		if (string.IsNullOrEmpty(data))
			return data;

		using HMACSHA256 hmac = new(keyRing.GetKey(keyId));
		return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(data)));
	}

	/// <inheritdoc />
	/// <exception cref="NotSupportedException">
	/// A blind index (keyed HMAC) is one-way by definition -- there is no key material that reverses it.
	/// </exception>
	public string? Unprotect(string keyId, string? data) =>
		throw new NotSupportedException("A blind index (keyed HMAC) is one-way by definition and cannot be unprotected.");
}
