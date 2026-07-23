using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Norse.Persistence.EntityFramework.Design.SqlServer;

namespace Norse.Identity.Migrations.SqlServer;

/// <summary>
/// Design-time factory for <see cref="NorseIdentityDbContext"/>, used only by <c>dotnet ef</c> tooling
/// (e.g. <c>dotnet ef migrations add</c>) to construct a context instance outside of DI at design time.
/// </summary>
/// <remarks>
/// Same ASP.NET Core Identity <c>SchemaVersion</c> gotcha as the PostgreSQL factory — see that type's
/// doc comment for the full explanation. Provider-independent: the fallback to
/// <see cref="IdentitySchemaVersions.Version1"/> happens in Identity's own model-building code, not
/// anything provider-specific.
/// </remarks>
public sealed class NorseIdentityDbContextFactory : NorseSqlServerDesignTimeDbContextFactory<NorseIdentityDbContext>
{
	/// <inheritdoc />
	protected override string DatabaseName => "norse_identity";

	/// <inheritdoc />
	protected override void ConfigureOptions(DbContextOptionsBuilder<NorseIdentityDbContext> builder, string connectionString)
	{
		var applicationServices = new ServiceCollection()
			.Configure<IdentityOptions>(o => o.Stores.SchemaVersion = IdentitySchemaVersions.Version3)
			.BuildServiceProvider();

		builder.UseApplicationServiceProvider(applicationServices);

		base.ConfigureOptions(builder, connectionString);
	}

	/// <inheritdoc />
	protected override NorseIdentityDbContext CreateContext(DbContextOptions<NorseIdentityDbContext> options) =>
		new(options);
}
