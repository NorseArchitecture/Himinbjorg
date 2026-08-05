using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;

namespace Norse.Identity.Web.Server;

/// <summary>
/// ASP.NET Core Identity's <see cref="IPersonalDataProtector"/> over the platform's per-subject key
/// seam: AES-256-GCM envelope encryption keyed by whichever subject <see cref="SubjectCryptoScope"/>
/// has ambient at the moment of the write. Envelope format:
/// <c>v1:{subjectId:D}:{base64(nonce(12) ∥ ciphertext ∥ tag(16))}</c> — self-describing, so
/// <see cref="Unprotect"/> never needs the ambient subject; only <see cref="Protect"/>, which writes,
/// does.
/// </summary>
/// <param name="keyStore">The subject key seam's custody store.</param>
public sealed class NorsePersonalDataProtector(ISubjectKeyStore keyStore) : IPersonalDataProtector
{
	const string EnvelopeVersion = "v1";
	const int NonceSizeInBytes = 12;
	const int TagSizeInBytes = 16;

	/// <inheritdoc />
	/// <exception cref="InvalidOperationException">
	/// No ambient <see cref="SubjectCryptoScope"/> is established. Encrypting to nobody would silently
	/// corrupt custody — every write path must establish the scope (see <see cref="NorseUserManager"/>)
	/// before a protected property is ever assigned.
	/// </exception>
	public string? Protect(string? data)
	{
		if (data is null)
			return null;

		var subjectId = SubjectCryptoScope.CurrentSubject ??
			throw new InvalidOperationException(
				"NorsePersonalDataProtector.Protect was called with no ambient SubjectCryptoScope -- every write path must establish the scope before encrypting.");

		// Sync-over-async bridge: IPersonalDataProtector is ASP.NET Core Identity's synchronous BCL
		// contract (the EF value converter it drives has no async conversion path), the local dev key
		// store is file-backed, and the production provider caches unwrapped DEKs in memory under the
		// platform's TTL law -- so this blocks on an operation that is either already cached or a local
		// file read, never a network round trip on the hot path.
		var key = keyStore.GetOrCreateAsync(subjectId).AsTask().GetAwaiter().GetResult();

		Span<byte> nonce = stackalloc byte[NonceSizeInBytes];
		RandomNumberGenerator.Fill(nonce);

		var plaintext = Encoding.UTF8.GetBytes(data);
		Span<byte> ciphertext = stackalloc byte[plaintext.Length];
		Span<byte> tag = stackalloc byte[TagSizeInBytes];

		using (AesGcm aes = new(key, TagSizeInBytes))
			aes.Encrypt(nonce, plaintext, ciphertext, tag);

		var envelope = new byte[NonceSizeInBytes + ciphertext.Length + TagSizeInBytes];
		nonce.CopyTo(envelope);
		ciphertext.CopyTo(envelope.AsSpan(NonceSizeInBytes));
		tag.CopyTo(envelope.AsSpan(NonceSizeInBytes + ciphertext.Length));

		return $"{EnvelopeVersion}:{subjectId:D}:{Convert.ToBase64String(envelope)}";
	}

	/// <inheritdoc />
	/// <exception cref="FormatException">The envelope is not shaped like this protector's own output.</exception>
	/// <exception cref="KeyDestroyedException">The subject's key was deliberately destroyed.</exception>
	/// <exception cref="KeyMissingException">No key and no destruction receipt exist -- an incident, not erasure.</exception>
	public string? Unprotect(string? data)
	{
		if (data is null)
			return null;

		var parts = data.Split(':', 3);
		if (parts.Length != 3 || parts[0] != EnvelopeVersion)
			throw new FormatException($"'{data}' is not a v1 NorsePersonalDataProtector envelope.");

		var subjectId = Guid.ParseExact(parts[1], "D");
		var envelope = Convert.FromBase64String(parts[2]);

		var nonce = envelope.AsSpan(0, NonceSizeInBytes);
		var tag = envelope.AsSpan(envelope.Length - TagSizeInBytes, TagSizeInBytes);
		var ciphertext = envelope.AsSpan(NonceSizeInBytes, envelope.Length - NonceSizeInBytes - TagSizeInBytes);

		// Sync-over-async bridge -- see Protect's remarks; the same bound applies to reads.
		var key = keyStore.GetAsync(subjectId).AsTask().GetAwaiter().GetResult().Match(
			available: static k => k,
			destroyed: static receipt => throw new KeyDestroyedException(receipt),
			missing: () => throw new KeyMissingException(subjectId));

		Span<byte> plaintext = stackalloc byte[ciphertext.Length];
		using (AesGcm aes = new(key, TagSizeInBytes))
			aes.Decrypt(nonce, ciphertext, tag, plaintext);

		return Encoding.UTF8.GetString(plaintext);
	}
}
