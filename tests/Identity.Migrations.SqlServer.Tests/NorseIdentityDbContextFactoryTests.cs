using Microsoft.EntityFrameworkCore;
using Norse.Identity.Web.Server;

namespace Norse.Identity.Migrations.SqlServer.Tests;

public sealed class NorseIdentityDbContextFactoryTests
{
	[Fact]
	void CreateDbContext_configures_schema_version_3_with_passkeys()
	{
		NorseIdentityDbContextFactory factory = new();
		using var context = factory.CreateDbContext([]);

		var entityType = context.Model.FindEntityType(typeof(NorseUserPasskey));

		entityType.ShouldNotBeNull();
		entityType.GetTableName().ShouldBe("UserPasskeys");
	}

	[Fact]
	void CreateDbContext_does_not_apply_snake_case_naming()
	{
		NorseIdentityDbContextFactory factory = new();
		using var context = factory.CreateDbContext([]);

		var entityType = context.Model.FindEntityType(typeof(NorseOpenIddictApplication));

		entityType.ShouldNotBeNull();
		entityType.FindProperty(nameof(NorseOpenIddictApplication.ClientId))!.GetColumnName().ShouldBe("ClientId");
	}
}
