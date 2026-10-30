using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;
using OpenIddict.EntityFrameworkCore.Models;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     Norse wrapper over OpenIddict's EF Core token entity, keyed by <see cref="Guid" />. Adds explicit
///     <see cref="ApplicationId" />/<see cref="AuthorizationId" />/<see cref="SessionId" /> FK scalars for the same
///     reason <see cref="NorseOpenIddictAuthorization.ApplicationId" /> exists — OpenIddict declares navigation
///     only, no FK scalar, on all three relationships.
/// </summary>
public sealed class NorseOpenIddictToken
	: OpenIddictEntityFrameworkCoreToken<Guid, NorseOpenIddictApplication, NorseOpenIddictAuthorization,
		NorseOpenIddictSession>,
		INorseEntity<NorseOpenIddictToken>
{
	/// <summary>
	///     Gets or sets the ID of the application this token is scoped to.
	/// </summary>
	public Guid? ApplicationId { get; set; }

	/// <summary>
	///     Gets or sets the ID of the authorization this token is bound to.
	/// </summary>
	public Guid? AuthorizationId { get; set; }

	/// <summary>
	///     Gets or sets the ID of the session this token belongs to.
	/// </summary>
	public Guid? SessionId { get; set; }

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseOpenIddictToken> builder)
	{
		builder.ToTable("Tokens");
		builder.Property(static t => t.Payload).HasMaxLength(-1);
		builder.Property(static t => t.Properties).HasMaxLength(-1);
		builder
			.HasOne(static t => t.Application)
			.WithMany(static a => a.Tokens)
			.HasForeignKey(static t => t.ApplicationId);

		builder
			.HasOne(static t => t.Authorization)
			.WithMany(static a => a.Tokens)
			.HasForeignKey(static t => t.AuthorizationId);

		builder
			.HasOne(static t => t.Session)
			.WithMany(static s => s.Tokens)
			.HasForeignKey(static t => t.SessionId);
	}
}
