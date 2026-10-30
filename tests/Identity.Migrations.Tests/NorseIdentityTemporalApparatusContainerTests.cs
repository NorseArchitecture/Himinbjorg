using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;
using Norse.Identity.Migrations.PostgreSQL;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.PostgreSQL;

namespace Norse.Identity.Migrations.Tests;

/// <summary>
///     The temporal apparatus against a real <c>postgres:19rc1</c> server: <c>InitialCreate</c> applies
///     clean and the full apparatus stands for the eight ruled tables — and for nothing else. This realm
///     keeps exactly one <c>InitialCreate</c> per provider (squashed in place, never stacked), so the
///     apparatus arrives at table birth through the chassis's <c>CreateTable</c> path (spec §3.1), not
///     through the §3.3 enable transition. Scaffolded SQL that reads right and refuses to apply is the
///     failure this suite exists to catch, which is why nothing here asserts on a migration name.
/// </summary>
/// <param name="fixture">The shared container.</param>
[Collection("Postgres")]
public sealed class NorseIdentityTemporalApparatusContainerTests(PostgresContainerFixture fixture)
{
	// The durable identity and authorization record (Himinbjörg#47 open question 4, ruled 2026-08-05; the
	// 2026-10-24 explicit-writes spec §3.1 took user_logins out; the Train 4 spec §4.3 added resources), by
	// physical table name. The entity-side pin lives in Identity.EntityFramework.Tests.
	static readonly string[] _temporalTables =
	[
		"applications", "resources", "role_claims", "roles", "scopes", "user_claims", "user_roles", "users"
	];

	// Secret stores, counters, and prunable runtime state -- user_credentials is the users fragment holding the
	// credential churn and lookup hashes, and user_logins left the temporal set by the same spec. The challenge ledger
	// and the verification cursor (T3-32/T3-28) are runtime state, never history, and so are OpenIddict 8's sessions
	// (Train 4 spec §4.3), bulk-pruned like authorizations and tokens.
	static readonly string[] _plainTables =
	[
		"authorizations", "consumed_passkey_challenges", "sessions", "subject_keys", "tokens", "user_credentials",
		"user_logins", "user_passkeys", "user_tokens", "verification_cursors"
	];

	// EF's own bookkeeping table, under the naming convention.
	const string MigrationsHistoryTable = "__EFMigrationsHistory";

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

	[Fact]
	async Task The_catalog_holds_exactly_the_ruled_temporal_and_plain_tables()
	{
		await using var context = await MigrateAsync();

		// Exhaustive both ways: a table the spec never ruled on, or a ruled table gone missing, fails here.
		(await TablesAsync(context)).ShouldBe(_temporalTables
			.SelectMany(static table => new[] { table, $"{table}_history" })
			.Concat(_plainTables)
			.Append(MigrationsHistoryTable)
			.Order(StringComparer.Ordinal));
		(await SystemPeriodTablesAsync(context)).ShouldBe(_temporalTables);
	}

	[Fact]
	async Task The_only_check_constraint_is_email_is_user_name_on_the_credentials_fragment()
	{
		await using var context = await MigrateAsync();

		// Schema-wide, so a CHECK that landed on users (where EF's entity-level form would put it) fails too.
		(await context.Database.SqlQuery<string>(
			$"""
			SELECT format('%s.%s %s', c.relname, k.conname, pg_catalog.pg_get_constraintdef(k.oid)) AS "Value"
			FROM pg_catalog.pg_constraint k
				JOIN pg_catalog.pg_class c ON c.oid = k.conrelid
				JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND k.contype = 'c'
			ORDER BY 1
			""").ToListAsync(Cancellation)).ShouldBe(
		[
			"user_credentials.ck_user_credentials_email_is_user_name CHECK (((normalized_email)::text = (normalized_user_name)::text))"
		]);
	}

	[Theory]
	[InlineData("user_credentials", "normalized_email")]
	[InlineData("user_credentials", "normalized_user_name")]
	[InlineData("user_claims", "claim_value")]
	[InlineData("user_claims", "claim_value_hash")]
	async Task The_lookup_hashes_and_the_claim_value_and_its_hash_are_NOT_NULL(string table, string column)
	{
		await using var context = await MigrateAsync();
		var qualified = $"public.{table}";

		(await context.Database.SqlQuery<bool>(
			$"""
			SELECT attnotnull AS "Value" FROM pg_catalog.pg_attribute
			WHERE attrelid = {qualified}::regclass AND attname = {column} AND NOT attisdropped
			""").SingleAsync(Cancellation)).ShouldBeTrue($"{table}.{column} should be NOT NULL");
	}

	[Theory]
	[InlineData("user_name_index",
		"CREATE UNIQUE INDEX user_name_index ON public.user_credentials USING btree (normalized_user_name)")]
	[InlineData("ix_user_claims_user_id_claim_type_claim_value_hash",
		"CREATE UNIQUE INDEX ix_user_claims_user_id_claim_type_claim_value_hash ON public.user_claims USING btree (user_id, claim_type, claim_value_hash)")]
	async Task The_user_name_and_claim_hash_indexes_are_unique_and_unfiltered(string index, string definition)
	{
		await using var context = await MigrateAsync();

		// The full definition: its table, its uniqueness, its key columns in order, and no WHERE clause.
		(await context.Database.SqlQuery<string>(
			$"""
			SELECT pg_catalog.pg_get_indexdef(c.oid) AS "Value"
			FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relkind = 'i' AND c.relname = {index}
			""").SingleAsync(Cancellation)).ShouldBe(definition);
	}

	[Fact]
	async Task The_claim_hash_is_a_stored_generated_sha256_of_the_utf8_claim_value()
	{
		await using var context = await MigrateAsync();

		(await context.Database.SqlQuery<string>(
			$"""
			SELECT format('%s %s %s', a.attgenerated, pg_catalog.format_type(a.atttypid, a.atttypmod),
				pg_catalog.pg_get_expr(d.adbin, d.adrelid)) AS "Value"
			FROM pg_catalog.pg_attribute a
				JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
			WHERE a.attrelid = 'public.user_claims'::regclass AND a.attname = 'claim_value_hash'
			""").SingleAsync(Cancellation)).ShouldBe("s bytea norse_utf8_sha256(claim_value)");
		// IMMUTABLE is what lets a generation expression call it at all (convert_to alone is STABLE).
		(await context.Database.SqlQuery<string>(
			$"""
			SELECT format('%s(%s) returns %s volatile=%s strict=%s parallel=%s', p.proname,
				pg_catalog.pg_get_function_arguments(p.oid), pg_catalog.pg_get_function_result(p.oid),
				p.provolatile, p.proisstrict, p.proparallel) AS "Value"
			FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
			WHERE n.nspname = 'public' AND p.proname = 'norse_utf8_sha256'
			""").SingleAsync(Cancellation)).ShouldBe(
			"norse_utf8_sha256(text) returns bytea volatile=i strict=t parallel=s");
		// The FIPS 180-2 test vector: SHA-256 of the UTF-8 bytes of "abc".
		(await context.Database.SqlQuery<string>(
				$"""SELECT encode(norse_utf8_sha256('abc'), 'hex') AS "Value" """)
			.SingleAsync(Cancellation)).ShouldBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	}

	/// <summary>
	///     Migrating is idempotent, so every fact here can stand the schema up for itself rather than
	///     depending on which class in the collection ran first.
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

	/// <summary>Every ordinary table in the schema.</summary>
	static Task<List<string>> TablesAsync(NorseIdentityDbContext context) =>
		context.Database.SqlQuery<string>(
			$"""
			SELECT c.relname AS "Value"
			FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relkind = 'r'
			ORDER BY c.relname COLLATE "C"
			""").ToListAsync(Cancellation);

	/// <summary>Every main table carrying the database-owned period: history tables carry one too, so they are excluded.</summary>
	static Task<List<string>> SystemPeriodTablesAsync(NorseIdentityDbContext context) =>
		context.Database.SqlQuery<string>(
			$"""
			SELECT c.relname AS "Value"
			FROM pg_catalog.pg_attribute a
				JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
				JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.attname = 'system_period' AND NOT a.attisdropped
				AND c.relname NOT LIKE '%\_history'
			ORDER BY c.relname COLLATE "C"
			""").ToListAsync(Cancellation);

	/// <summary>
	///     Ordinary tables and views only ('r', 'v'): indexes and sequences live in <c>pg_class</c> too and
	///     cannot outlive the table they belong to, so counting them would only add noise.
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
	///     Trigger name and the function it is bound to, together: a trigger surviving under its old name and
	///     still bound to a retired function is the failure a name-only check would sail past.
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
