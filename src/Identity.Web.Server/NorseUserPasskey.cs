using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity.Web.Server;

/// <summary>
/// Norse platform ASP.NET Core Identity passkey entity, keyed by <see cref="Guid"/>.
/// </summary>
public sealed class NorseUserPasskey : IdentityUserPasskey<Guid>, INorseEntity<NorseUserPasskey>
{
	/// <summary>
	/// The user this passkey belongs to.
	/// </summary>
	public NorseUser User { get; init; } = null!;

	/// <summary>
	/// Renames the table to strip the "AspNet" prefix, matching every other Identity entity's naming.
	/// Key and the <see cref="IdentityUserPasskey{TKey}.Data"/> complex JSON property are already
	/// configured by <c>IdentityUserContext.OnModelCreatingVersion3</c> and must not be re-declared here
	/// -- a second <c>ComplexProperty</c>/<c>OwnsOne</c> registration for <c>Data</c> throws at model
	/// build time.
	/// </summary>
	public static void Configure(EntityTypeBuilder<NorseUserPasskey> builder) =>
		builder.ToTable("UserPasskeys");
}
