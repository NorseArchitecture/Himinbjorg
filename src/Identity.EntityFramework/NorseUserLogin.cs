using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity.EntityFramework;

/// <summary>
///     Norse platform ASP.NET Core Identity external-login entity, keyed by <see cref="Guid" />.
///     Not system-versioned: the 2026-10-24 explicit-writes spec §3.1 took external-login links out of the
///     temporal set, superseding the 2026-08-05 ruling (Himinbjörg#47 open question 4) that kept a disconnected
///     link as identity record.
/// </summary>
public sealed class NorseUserLogin : IdentityUserLogin<Guid>, INorseEntity<NorseUserLogin>
{
	/// <summary>
	///     The user this external login belongs to.
	/// </summary>
	public NorseUser User { get; init; } = null!;

	/// <inheritdoc />
	public static void Configure(EntityTypeBuilder<NorseUserLogin> builder)
	{
		builder.ToTable("UserLogins");
		builder.Property(static l => l.LoginProvider).HasMaxLength(128);
		builder.Property(static l => l.ProviderKey).HasMaxLength(256);
		builder.Property(static l => l.ProviderDisplayName).HasMaxLength(256);
	}
}
