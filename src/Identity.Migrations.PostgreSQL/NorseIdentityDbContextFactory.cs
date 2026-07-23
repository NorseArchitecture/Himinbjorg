using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Norse.Identity.Web.Server;
using Norse.Persistence.EntityFramework.Design.PostgreSQL;

namespace Norse.Identity.Migrations.PostgreSQL;

/// <summary>
/// Design-time factory for <see cref="NorseIdentityDbContext"/>, used only by <c>dotnet ef</c> tooling
/// (e.g. <c>dotnet ef migrations add</c>) to construct a context instance outside of DI at design time.
/// </summary>
/// <remarks>
/// ASP.NET Core Identity's base <c>OnModelCreating</c> reads
/// <c>IOptions&lt;IdentityOptions&gt;.Value.Stores.SchemaVersion</c> off the context's
/// <c>ApplicationServiceProvider</c> — not the (dead, never-consulted) protected <c>SchemaVersion</c>
/// property — to decide which passkey/OpenIddict schema shape to emit. Without an application service
/// provider supplying <see cref="IdentitySchemaVersions.Version3"/>, ASP.NET Core Identity silently
/// falls back to <see cref="IdentitySchemaVersions.Version1"/> and omits the passkey table entirely.
/// </remarks>
public sealed class NorseIdentityDbContextFactory : NorsePostgreSqlDesignTimeDbContextFactory<NorseIdentityDbContext>
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
