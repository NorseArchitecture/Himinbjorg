using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;
using OpenIddict.EntityFrameworkCore.Models;

namespace Norse.Identity;

/// <summary>
/// Norse wrapper over OpenIddict's EF Core authorization entity, keyed by <see cref="Guid"/>. Adds an
/// explicit <see cref="ApplicationId"/> FK scalar — OpenIddict's own base class declares only the
/// <see cref="OpenIddictEntityFrameworkCoreAuthorization{TKey,TApplication,TToken}.Application"/>
/// navigation, leaving EF to fall back to a shadow FK, which the platform's navigation/FK law forbids
/// outside audit columns.
/// </summary>
public sealed class NorseOpenIddictAuthorization
	: OpenIddictEntityFrameworkCoreAuthorization<Guid, NorseOpenIddictApplication, NorseOpenIddictToken>,
	  INorseEntity<NorseOpenIddictAuthorization>
{
	/// <summary>
	/// Gets or sets the ID of the application this authorization belongs to.
	/// </summary>
	public Guid? ApplicationId { get; init; }

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseOpenIddictAuthorization> builder)
	{
		builder.Property(a => a.Scopes).HasMaxLength(-1);
		builder.Property(a => a.Properties).HasMaxLength(-1);
		builder.HasOne(a => a.Application).WithMany(app => app.Authorizations).HasForeignKey(a => a.ApplicationId);
	}
}
