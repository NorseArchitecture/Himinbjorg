using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;
using Norse.Identity.Migrations.PostgreSQL;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.PostgreSQL;

namespace Norse.Identity.Migrations.Tests;

/// <summary>
/// The temporal apparatus against a real <c>postgres:19beta2</c> server: <c>InitialCreate</c> applies
/// clean and the full apparatus stands for the eight ruled tables — and for nothing else. This realm
/// keeps exactly one <c>InitialCreate</c> per provider (squashed in place, never stacked), so the
/// apparatus arrives at table birth through the chassis's <c>CreateTable</c> path (spec §3.1), not
/// through the §3.3 enable transition. Scaffolded SQL that reads right and refuses to apply is the
/// failure this suite exists to catch, which is why nothing here asserts on a migration name.
/// </summary>
/// <param name="fixture">The shared container.</param>
[Collection("Postgres")]
public sealed class NorseIdentityTemporalApparatusContainerTests(PostgresContainerFixture fixture)
{
	// The durable identity and authorization record (Himinbjörg#47 open question 4, ruled 2026-08-05),
	// by physical table name. The entity-side pin lives in Identity.EntityFramework.Tests.
	static readonly string[] _temporalTables =
	[
		"applications", "role_claims", "roles", "scopes", "user_claims", "user_logins", "user_roles", "users"
	];

	// Secret stores, counters, and prunable runtime state.
	static readonly string[] _plainTables =
	[
		"authorizations", "subject_keys", "tokens", "user_passkeys", "user_tokens"
	];

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task MigrateAsync_stands_up_the_temporal_apparatus_on_the_eight_ruled_tables()
	{
		await using var context = await MigrateAsync();

		foreach (var table in _temporalTables)
		{
			(await HasSystemPeriodAsync(context, table)).ShouldBeTrue($"{table} should carry system_period");
			(await RelationsAsync(context, $"{table}\\_%")).ShouldBe([$"{table}_history", $"{table}_timeline"]);
			(await FunctionsAsync(context, $"{table}\\_versioning")).ShouldBe([$"{table}_versioning"]);
			(await TriggerBindingsAsync(context, table)).ShouldBe(
			[
				$"{table}_versioning_delete -> {table}_versioning",
				$"{table}_versioning_insert -> {table}_versioning",
				$"{table}_versioning_update -> {table}_versioning"
			]);
		}
	}

	[Fact]
	async Task The_ruled_out_tables_take_no_apparatus_at_all()
	{
		await using var context = await MigrateAsync();

		foreach (var table in _plainTables)
		{
			(await HasSystemPeriodAsync(context, table)).ShouldBeFalse($"{table} should not carry system_period");
			(await RelationsAsync(context, $"{table}\\_history")).ShouldBeEmpty();
			(await RelationsAsync(context, $"{table}\\_timeline")).ShouldBeEmpty();
			(await TriggerBindingsAsync(context, table)).ShouldBeEmpty();
		}
	}

	/// <summary>
	/// Migrating is idempotent, so every fact here can stand the schema up for itself rather than
	/// depending on which class in the collection ran first.
	/// </summary>
	async Task<NorseIdentityDbContext> MigrateAsync()
	{
		DbContextOptionsBuilder<NorseIdentityDbContext> optionsBuilder = new();
		optionsBuilder.ApplyNorseProviderOptions(NorsePostgresEfProvider.Instance,
			fixture.ConnectionString, typeof(NorseIdentityDbContextFactory).Assembly.GetName().Name);
		NorseIdentityDbContext context = new(optionsBuilder.Options);
		NorseIdentityMigrationContributor contributor = new(context);
		await contributor.MigrateAsync(Cancellation);
		return context;
	}

	// system_period is database-owned and outside the EF model (spec §3.2), so every reading below is a
	// deliberate trip through the catalog rather than a gap in the mapping.
	static Task<bool> HasSystemPeriodAsync(NorseIdentityDbContext context, string table)
	{
		var qualified = $"public.{table}";
		return context.Database.SqlQuery<bool>(
			$"""
			SELECT EXISTS (
				SELECT 1 FROM pg_catalog.pg_attribute
				WHERE attrelid = {qualified}::regclass
					AND attname = 'system_period' AND NOT attisdropped) AS "Value"
			""").SingleAsync(Cancellation);
	}

	/// <summary>
	/// Ordinary tables and views only ('r', 'v'): indexes and sequences live in <c>pg_class</c> too and
	/// cannot outlive the table they belong to, so counting them would only add noise.
	/// </summary>
	static Task<List<string>> RelationsAsync(NorseIdentityDbContext context, string pattern) =>
		context.Database.SqlQuery<string>(
			$"""
			SELECT c.relname AS "Value"
			FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relkind IN ('r', 'v') AND c.relname LIKE {pattern}
			ORDER BY c.relname
			""").ToListAsync(Cancellation);

	static Task<List<string>> FunctionsAsync(NorseIdentityDbContext context, string pattern) =>
		context.Database.SqlQuery<string>(
			$"""
			SELECT p.proname AS "Value"
			FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
			WHERE n.nspname = 'public' AND p.proname LIKE {pattern}
			ORDER BY p.proname
			""").ToListAsync(Cancellation);

	/// <summary>
	/// Trigger name and the function it is bound to, together: a trigger surviving under its old name and
	/// still bound to a retired function is the failure a name-only check would sail past.
	/// </summary>
	static Task<List<string>> TriggerBindingsAsync(NorseIdentityDbContext context, string table)
	{
		var qualified = $"public.{table}";
		return context.Database.SqlQuery<string>(
			$"""
			SELECT t.tgname || ' -> ' || p.proname AS "Value"
			FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
			WHERE t.tgrelid = {qualified}::regclass AND NOT t.tgisinternal
			ORDER BY t.tgname
			""").ToListAsync(Cancellation);
	}
}
