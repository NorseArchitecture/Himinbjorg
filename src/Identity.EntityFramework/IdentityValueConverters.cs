using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Norse.Identity.EntityFramework;

/// <summary>
/// Shared value converters for ASP.NET Core Identity's stamp/hash columns — used by both
/// <see cref="NorseUser"/> and <see cref="NorseRole"/>. Realm-internal; not promoted to Urðarbrunnr
/// since no other realm runs ASP.NET Core Identity today.
/// </summary>
static class IdentityValueConverters
{
	// ValueConverter lambdas are expression trees — CS8122 forbids `is` patterns inside them, so
	// these null checks stay `!= null` by language constraint, not by choice.
	public static readonly ValueConverter<string?, Guid?> Stamp = new(
		static s => s != null ? Guid.Parse(s) : null,
		static g => g.HasValue ? g.ToString() : null);

	public static readonly ValueConverter<string?, byte[]?> Hash = new(
		static s => s != null ? Convert.FromBase64String(s) : null,
		static b => b != null ? Convert.ToBase64String(b) : null);
}
