using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;

namespace Norse.Identity.Web.Server;

/// <summary>
/// ASP.NET Core Identity's <see cref="ILookupProtectorKeyRing"/> delegating to the platform's
/// <see cref="ILookupKeyRing"/> seam. <see cref="this[string]"/> is a pass-through of the key id itself,
/// not key material: <see cref="ILookupKeyRing"/> hands out raw key bytes only through
/// <see cref="ILookupKeyRing.GetKey"/>, which <see cref="NorseLookupProtector"/> calls directly with the
/// <c>keyId</c> it is given -- nothing in this seam ever routes key bytes through Identity's
/// <c>string</c>-typed indexer.
/// </summary>
/// <param name="keyRing">The lookup-plane keyring.</param>
public sealed class NorseLookupProtectorKeyRing(ILookupKeyRing keyRing) : ILookupProtectorKeyRing
{
	/// <inheritdoc />
	public string CurrentKeyId =>
		keyRing.CurrentKeyId;

	/// <inheritdoc />
	public string this[string keyId] =>
		keyId;

	/// <inheritdoc />
	public IEnumerable<string> GetAllKeyIds() =>
		keyRing.KeyIds;
}
