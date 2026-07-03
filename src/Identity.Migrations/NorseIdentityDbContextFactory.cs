using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.DependencyInjection;
using Norse.EntityFramework;

namespace Norse.Identity.Migrations;

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
public sealed class NorseIdentityDbContextFactory : IDesignTimeDbContextFactory<NorseIdentityDbContext>
{
	/// <inheritdoc />
	public NorseIdentityDbContext CreateDbContext(string[] args)
	{
		var connectionString =
			Environment.GetEnvironmentVariable("DOTNET_EFTOOLS_CONNECTIONSTRING")
			?? "Host=localhost;Port=5432;Database=norse_identity;Username=postgres;Password=devpassword";

		var applicationServices = new ServiceCollection()
			.Configure<IdentityOptions>(o => o.Stores.SchemaVersion = IdentitySchemaVersions.Version3)
			.BuildServiceProvider();

		var optionsBuilder = new DbContextOptionsBuilder<NorseIdentityDbContext>()
			.UseApplicationServiceProvider(applicationServices)
			.UseNpgsql(connectionString,
				o => o.MigrationsAssembly(typeof(NorseIdentityDbContextFactory).Assembly.GetName().Name));

		// This factory only ever targets Postgres (the connection string above is Npgsql-style), so
		// applying snake_case naming unconditionally here is correct -- unlike the DI-registration
		// extensions elsewhere in this codebase, there's no provider ambiguity to gate it behind.
		NorseDbContextOptionsExtensions.ApplyNorseConventions(optionsBuilder);

		var options = optionsBuilder.Options;

		return new NorseIdentityDbContext(options);
	}
}
