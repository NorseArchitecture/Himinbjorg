using Norse.Persistence.EntityFramework.Design;

namespace Norse.Identity.Migrations;

/// <summary>
/// Migration contributor for <see cref="NorseIdentityDbContext"/>, discovered by the migrations
/// service and executed at startup to apply pending Identity/OpenIddict schema migrations.
/// </summary>
/// <param name="context">The Identity context instance resolved from DI.</param>
[MigrationConnectionString("norse_identity")]
public sealed class NorseIdentityMigrationContributor(NorseIdentityDbContext context)
	: EfMigrationContributor<NorseIdentityDbContext>(context)
{
	/// <inheritdoc />
	public override string Name => "Norse.Identity";
}
