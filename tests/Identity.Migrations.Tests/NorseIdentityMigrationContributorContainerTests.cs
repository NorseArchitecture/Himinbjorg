using Microsoft.EntityFrameworkCore;
using Norse.Identity.Migrations.PostgreSQL;
using Norse.Identity.Web.Server;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.PostgreSQL;

namespace Norse.Identity.Migrations.Tests;

[Collection("Postgres")]
public sealed class NorseIdentityMigrationContributorContainerTests(PostgresContainerFixture fixture)
{
	[Fact]
	async Task MigrateAsync_applies_InitialCreate_and_stands_up_the_v3_passkey_table()
	{
		var cancellationToken = TestContext.Current.CancellationToken;
		DbContextOptionsBuilder<NorseIdentityDbContext> optionsBuilder = new();
		optionsBuilder.ApplyNorseProviderOptions(NorsePostgresEfProvider.Instance,
			fixture.ConnectionString, typeof(NorseIdentityDbContextFactory).Assembly.GetName().Name);
		await using NorseIdentityDbContext context = new(optionsBuilder.Options);
		NorseIdentityMigrationContributor contributor = new(context);

		await contributor.MigrateAsync(cancellationToken);

		(await context.Database.GetAppliedMigrationsAsync(cancellationToken))
			.ShouldContain(m => m.Contains("InitialCreate", StringComparison.Ordinal));
		// Queries the physical table: 42P01 here — not a vacuous green — if SchemaVersion silently
		// fell back to Version1 and the passkey table was never created.
		(await context.Set<NorseUserPasskey>().AnyAsync(cancellationToken)).ShouldBeFalse();
	}
}
