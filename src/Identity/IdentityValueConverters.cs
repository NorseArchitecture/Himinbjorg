using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Norse.Identity;

/// <summary>
/// Shared value converters for ASP.NET Core Identity's stamp/hash columns — used by both
/// <see cref="NorseUser"/> and <see cref="NorseRole"/>. Realm-internal; not promoted to Urdarbrunnr
/// since no other realm runs ASP.NET Core Identity today.
/// </summary>
static class IdentityValueConverters
{
	public static readonly ValueConverter<string?, Guid?> Stamp = new(
		static s => s != null ? Guid.Parse(s) : null,
		static g => g.HasValue ? g.ToString() : null);

	public static readonly ValueConverter<string?, byte[]?> Hash = new(
		static s => s != null ? Convert.FromBase64String(s) : null,
		static b => b != null ? Convert.ToBase64String(b) : null);
}
