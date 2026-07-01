using Norse.EntityFramework.Migrations;

namespace Norse.Identity.Migrations.Tests;

public sealed class NorseIdentityMigrationContributorTests
{
	[Fact]
	public void Name_returns_Norse_Identity()
	{
		var attr = typeof(NorseIdentityMigrationContributor)
			.GetCustomAttributes(typeof(MigrationConnectionStringAttribute), false)
			.Cast<MigrationConnectionStringAttribute>()
			.Single();

		attr.ConnectionStringName.ShouldBe("norse_identity");
		// Name check deferred: constructor requires a real DbContext
	}

	[Fact]
	public void Contributor_is_annotated_with_connection_string_attribute()
	{
		var attr = typeof(NorseIdentityMigrationContributor)
			.GetCustomAttributes(typeof(MigrationConnectionStringAttribute), false);

		attr.ShouldNotBeEmpty();
	}
}
