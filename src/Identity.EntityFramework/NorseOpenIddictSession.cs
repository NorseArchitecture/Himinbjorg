using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;
using OpenIddict.EntityFrameworkCore.Models;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     Norse wrapper over OpenIddict 8's EF Core session entity, keyed by <see cref="Guid" />. Adds explicit
///     <see cref="ApplicationId" />/<see cref="AuthorizationId" /> FK scalars for the same reason
///     <see cref="NorseOpenIddictAuthorization.ApplicationId" /> exists — OpenIddict declares navigation only, no FK
///     scalar, on both relationships. Non-temporal: sessions are bulk-pruned runtime state, like authorizations and
///     tokens.
/// </summary>
public sealed class NorseOpenIddictSession
	: OpenIddictEntityFrameworkCoreSession<Guid, NorseOpenIddictApplication, NorseOpenIddictAuthorization,
			NorseOpenIddictToken>,
		INorseEntity<NorseOpenIddictSession>
{
	/// <summary>
	///     Gets or sets the ID of the application this session belongs to.
	/// </summary>
	public Guid? ApplicationId { get; set; }

	/// <summary>
	///     Gets or sets the ID of the authorization this session is bound to.
	/// </summary>
	public Guid? AuthorizationId { get; set; }

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseOpenIddictSession> builder)
	{
		builder.ToTable("Sessions");
		// A JSON-string value converter OpenIddict 8 leaves unbounded by omission.
		builder.Property(static s => s.Properties).HasMaxLength(-1);
		builder
			.HasOne(static s => s.Application)
			.WithMany(static a => a.Sessions)
			.HasForeignKey(static s => s.ApplicationId);

		builder
			.HasOne(static s => s.Authorization)
			.WithMany(static a => a.Sessions)
			.HasForeignKey(static s => s.AuthorizationId);
	}
}
