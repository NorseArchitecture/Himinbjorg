using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.DependencyInjection;
using Norse.Persistence.EntityFramework.Design;

namespace Norse.Identity.Migrations.SqlServer;

/// <summary>
/// Installs <see cref="DdlEmittingMigrationsScaffolder"/> for <c>dotnet ef</c> tooling, so every
/// <c>migrations add</c>/<c>migrations remove</c> run against this project also refreshes
/// <c>schema/norse_identity.sql</c>.
/// </summary>
sealed class DesignTimeServices : IDesignTimeServices
{
	public void ConfigureDesignTimeServices(IServiceCollection services) =>
		services.AddNorseDesignTimeServices("norse_identity");
}
