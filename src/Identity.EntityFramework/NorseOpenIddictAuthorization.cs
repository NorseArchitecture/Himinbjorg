using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;
using OpenIddict.EntityFrameworkCore.Models;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     Norse wrapper over OpenIddict's EF Core authorization entity, keyed by <see cref="Guid" />. Adds an
///     explicit <see cref="ApplicationId" /> FK scalar — OpenIddict's own base class declares only the
///     <see cref="OpenIddictEntityFrameworkCoreAuthorization{TKey,TApplication,TSession,TToken}.Application" />
///     navigation, leaving EF to fall back to a shadow FK, which the platform's navigation/FK law forbids
///     outside audit columns.
/// </summary>
public sealed class NorseOpenIddictAuthorization
	: OpenIddictEntityFrameworkCoreAuthorization<Guid, NorseOpenIddictApplication, NorseOpenIddictSession,
		NorseOpenIddictToken>,
		INorseEntity<NorseOpenIddictAuthorization>
{
	/// <summary>
	///     Gets or sets the ID of the application this authorization belongs to.
	/// </summary>
	public Guid? ApplicationId { get; set; }

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseOpenIddictAuthorization> builder)
	{
		builder.ToTable("Authorizations");
		// A JSON-string value converter OpenIddict 8 leaves unbounded by omission; Scopes is a string[] primitive
		// collection and takes no length.
		builder.Property(static a => a.Properties).HasMaxLength(-1);
		builder
			.HasOne(static a => a.Application)
			.WithMany(static app => app.Authorizations)
			.HasForeignKey(static a => a.ApplicationId);
	}
}
