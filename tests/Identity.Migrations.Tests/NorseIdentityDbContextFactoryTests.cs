using Microsoft.EntityFrameworkCore;

namespace Norse.Identity.Migrations.Tests;

public sealed class NorseIdentityDbContextFactoryTests
{
	[Fact]
	void CreateDbContext_configures_schema_version_3_with_passkeys()
	{
		NorseIdentityDbContextFactory factory = new();
		using var context = factory.CreateDbContext([]);

		var entityType = context.Model.FindEntityType(typeof(NorseUserPasskey));

		// A null-conditional chain here would let this test pass vacuously if the entity type is
		// missing entirely (exactly what happens when SchemaVersion silently falls back to Version1
		// and Ignore<TUserPasskey>() strips it from the model) — assert not-null first.
		entityType.ShouldNotBeNull();
		entityType.GetTableName().ShouldBe("AspNetUserPasskeys");
	}
}
