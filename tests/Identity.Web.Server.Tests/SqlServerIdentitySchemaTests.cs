using System.Globalization;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Norse.Identity.EntityFramework;
using OpenIddict.Abstractions;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The catalog's own word on the identity schema <see cref="SqlServerIdentityFixture" /> stood up through the
///     checked-in SQL Server <c>InitialCreate</c> (2026-10-24 explicit-writes spec §3, §3.1, §4.6, §6) -- the SQL
///     Server twin of <c>Identity.Migrations.Tests</c>' <c>NorseIdentityTemporalApparatusContainerTests</c>, and the
///     one home of each catalog fact on this provider: the temporal and plain table sets, system versioning on
///     <c>Users</c> alone with HIDDEN periods, the credentials fragment's CHECK, the NOT NULLs, the two unique
///     indexes, the claim hash, and the passkey payload's native <c>json</c>. Never a migration name -- the squash
///     cycle would break it.
/// </summary>
/// <remarks>
///     Physical names are written out, as the Postgres twin writes its own: this suite pins what the engine holds,
///     so it must not ask the model what to expect. Whether the database refuses a write that breaks the CHECK or a
///     NOT NULL is behavior, and lives in <see cref="UserCredentialsConstraintSuite" />.
/// </remarks>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerIdentitySchemaTests(SqlServerIdentityFixture fixture)
{
	const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	// The durable identity and authorization record (spec §3.1; Resources from the Train 4 spec §4.3): Users through
	// Urðarbrunnr's principal-table-only seam, the other seven through EF-native temporal.
	static readonly string[] _temporalTables =
		["Applications", "Resources", "RoleClaims", "Roles", "Scopes", "UserClaims", "UserRoles", "Users"];

	// Secret stores, counters, and prunable runtime state (spec §3.1; the challenge ledger and the verification
	// cursor, T3-32/T3-28; OpenIddict 8's sessions, Train 4 spec §4.3), plus EF's own bookkeeping table.
	static readonly string[] _plainTables =
	[
		"Authorizations", "ConsumedPasskeyChallenges", "Sessions", "SubjectKeys", "Tokens", "UserCredentials",
		"UserLogins", "UserPasskeys", "UserTokens", "VerificationCursors", "__EFMigrationsHistory"
	];

	public static bool IsTestable => SqlServerIdentityFixture.IsTestable;

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	async Task Exactly_the_eight_ruled_tables_are_system_versioned_each_into_its_own_history()
	{
		fixture.SkipUnlessAvailable();
		var (context, _) = await fixture.CreateScopeAsync();

		// 2 is SYSTEM_VERSIONED_TEMPORAL_TABLE; a history table is 1 and never counts.
		(await context.Database.SqlQuery<string>(
			$"""
			SELECT CONCAT(t.name, N' -> ', h.name) AS Value
			FROM sys.tables t JOIN sys.tables h ON h.object_id = t.history_table_id
			WHERE t.temporal_type = 2
			ORDER BY t.name
			""").ToListAsync(Cancellation)).ShouldBe(_temporalTables
			.Select(static table => $"{table} -> {table}History"));
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	async Task Exactly_the_ruled_plain_tables_are_non_temporal()
	{
		fixture.SkipUnlessAvailable();
		var (context, _) = await fixture.CreateScopeAsync();

		// 0 is NON_TEMPORAL_TABLE. Exhaustive: a table the spec never ruled on fails here.
		(await context.Database.SqlQuery<string>(
				$"SELECT name AS Value FROM sys.tables WHERE temporal_type = 0")
			.ToListAsync(Cancellation)).Order(StringComparer.Ordinal).ShouldBe(_plainTables.Order(StringComparer.Ordinal));
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	async Task Users_versions_with_hidden_periods_and_its_credentials_fragment_carries_none()
	{
		fixture.SkipUnlessAvailable();
		var (context, _) = await fixture.CreateScopeAsync();

		(await PeriodColumnsAsync(context, "Users")).ShouldBe(
		[
			"SystemPeriodEnd AS_ROW_END hidden=1",
			"SystemPeriodStart AS_ROW_START hidden=1"
		]);
		(await PeriodColumnsAsync(context, "UserCredentials")).ShouldBeEmpty();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	async Task The_only_check_constraint_is_email_is_user_name_on_the_credentials_fragment()
	{
		fixture.SkipUnlessAvailable();
		var (context, _) = await fixture.CreateScopeAsync();

		// Database-wide, so a CHECK that landed on Users (where EF's entity-level form would put it) fails too.
		(await context.Database.SqlQuery<string>(
			$"""
			SELECT CONCAT(OBJECT_NAME(parent_object_id), N'.', name, N' ', definition) AS Value
			FROM sys.check_constraints
			ORDER BY 1
			""").ToListAsync(Cancellation)).ShouldBe(
			["UserCredentials.CK_UserCredentials_EmailIsUserName ([NormalizedEmail]=[NormalizedUserName])"]);
	}

	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[InlineData("UserCredentials", "NormalizedEmail")]
	[InlineData("UserCredentials", "NormalizedUserName")]
	[InlineData("UserClaims", "ClaimValue")]
	[InlineData("UserClaims", "ClaimValueHash")]
	async Task The_lookup_hashes_and_the_claim_value_and_its_hash_are_NOT_NULL(string table, string column)
	{
		fixture.SkipUnlessAvailable();
		var (context, _) = await fixture.CreateScopeAsync();
		var qualified = $"dbo.{table}";

		(await context.Database.SqlQuery<bool>(
				$"SELECT is_nullable AS Value FROM sys.columns WHERE object_id = OBJECT_ID({qualified}) AND name = {column}")
			.SingleAsync(Cancellation)).ShouldBeFalse($"{table}.{column} should be NOT NULL");
	}

	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[InlineData("UserNameIndex", "UserCredentials unique=1 filtered=0 (NormalizedUserName)")]
	[InlineData("IX_UserClaims_UserId_ClaimType_ClaimValueHash",
		"UserClaims unique=1 filtered=0 (UserId,ClaimType,ClaimValueHash)")]
	async Task The_user_name_and_claim_hash_indexes_are_unique_and_unfiltered(string index, string definition)
	{
		fixture.SkipUnlessAvailable();
		var (context, _) = await fixture.CreateScopeAsync();

		// Its table, its uniqueness, no filter, and its key columns in key order.
		(await context.Database.SqlQuery<string>(
			$"""
			SELECT CONCAT(OBJECT_NAME(i.object_id), N' unique=', i.is_unique, N' filtered=', i.has_filter, N' (',
				STRING_AGG(c.name, N',') WITHIN GROUP (ORDER BY ic.key_ordinal), N')') AS Value
			FROM sys.indexes i
				JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
				JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
			WHERE i.name = {index} AND ic.key_ordinal > 0
			GROUP BY i.object_id, i.is_unique, i.has_filter
			""").SingleAsync(Cancellation)).ShouldBe(definition);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	async Task The_claim_hash_is_a_persisted_computed_binary_32_sha256_of_the_claim_value()
	{
		fixture.SkipUnlessAvailable();
		var (context, _) = await fixture.CreateScopeAsync();

		// The engine stores the definition normalized: CAST(... AS binary(32)) reads back as CONVERT, ISNULL as isnull.
		// ISNULL takes its first argument's type, so the 0x fallback leaves the column binary(32).
		(await context.Database.SqlQuery<string>(
			$"""
			SELECT CONCAT(TYPE_NAME(system_type_id), N'(', max_length, N') persisted=', is_persisted, N' ', definition)
				AS Value
			FROM sys.computed_columns
			WHERE object_id = OBJECT_ID(N'dbo.UserClaims') AND name = N'ClaimValueHash'
			""").SingleAsync(Cancellation)).ShouldBe(
			"binary(32) persisted=1 (isnull(CONVERT([binary](32),hashbytes('SHA2_256',[ClaimValue])),0x))");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	async Task The_passkey_payload_is_native_json()
	{
		fixture.SkipUnlessAvailable();
		var (context, _) = await fixture.CreateScopeAsync();

		var dataType = await context.Database.SqlQuery<string>(
				$"""
				SELECT t.name AS Value
				FROM sys.columns c JOIN sys.types t ON t.user_type_id = c.user_type_id
				WHERE c.object_id = OBJECT_ID(N'dbo.UserPasskeys') AND c.name = N'Data'
				""")
			.SingleAsync(Cancellation);

		dataType.ShouldBe("json");
	}

	// The H1 spike (Train 4 spec §4.2): OpenIddict 8 types what were JSON strings, and engine-native system versioning
	// must carry those columns into history unchanged. Written through the stock managers, the store's own write path,
	// and read back through EF-native TemporalAll(), so every version materializes through OpenIddict's mapping.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	async Task Json_typed_columns_survive_system_versioning()
	{
		fixture.SkipUnlessAvailable();
		using var scope = fixture.CreateOwnedScope();
		var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
		var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
		var resources = scope.ServiceProvider.GetRequiredService<IOpenIddictResourceManager>();
		var suffix = Guid.NewGuid().ToString("N");
		var property = JsonElement.Parse("""{"k": 1}""");
		string[] redirectUris = ["https://one.example/callback", "https://two.example/callback"];

		OpenIddictApplicationDescriptor applicationDescriptor = new()
		{
			ClientId = $"spike-{suffix}",
			ClientType = OpenIddictConstants.ClientTypes.Public,
			RedirectUris = { new(redirectUris[0]), new(redirectUris[1]) },
			Permissions = { OpenIddictConstants.Permissions.Endpoints.Authorization },
			Properties = { ["spike"] = property }
		};
		var application = await applications.CreateAsync(applicationDescriptor, Cancellation);
		applicationDescriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
		await applications.UpdateAsync(application, applicationDescriptor, Cancellation);

		OpenIddictScopeDescriptor scopeDescriptor = new()
		{
			Name = $"spike-scope-{suffix}",
			Resources = { "spike-api" },
			Properties = { ["spike"] = property }
		};
		var openIddictScope = await scopes.CreateAsync(scopeDescriptor, Cancellation);
		scopeDescriptor.Resources.Add("spike-api-2");
		await scopes.UpdateAsync(openIddictScope, scopeDescriptor, Cancellation);

		OpenIddictResourceDescriptor resourceDescriptor = new()
		{
			Name = $"urn:norse:spike-resource:{suffix}",
			DisplayNames = { [CultureInfo.InvariantCulture] = "Spike" },
			Properties = { ["spike"] = property }
		};
		var resource = await resources.CreateAsync(resourceDescriptor, Cancellation);
		resourceDescriptor.Description = "updated";
		await resources.UpdateAsync(resource, resourceDescriptor, Cancellation);

		var (context, _) = await fixture.CreateScopeAsync();
		var applicationId = ((NorseOpenIddictApplication)application).Id;
		var applicationVersions = await context.Set<NorseOpenIddictApplication>().TemporalAll()
			.Where(a => a.Id == applicationId)
			.OrderBy(static a => EF.Property<DateTime>(a, "SystemPeriodStart"))
			.ToListAsync(Cancellation);
		applicationVersions.Count.ShouldBe(2);
		applicationVersions.ShouldAllBe(a => a.RedirectUris!.Order(StringComparer.Ordinal).SequenceEqual(redirectUris));
		applicationVersions.ShouldAllBe(static a => a.Properties!["spike"].GetRawText() == """{"k":1}""");
		applicationVersions[0].Permissions.ShouldBe([OpenIddictConstants.Permissions.Endpoints.Authorization]);
		applicationVersions[1].Permissions!.Order(StringComparer.Ordinal).ShouldBe(
			[OpenIddictConstants.Permissions.Endpoints.Authorization, OpenIddictConstants.Permissions.Endpoints.Token]);

		var scopeId = ((NorseOpenIddictScope)openIddictScope).Id;
		var scopeVersions = await context.Set<NorseOpenIddictScope>().TemporalAll()
			.Where(s => s.Id == scopeId)
			.OrderBy(static s => EF.Property<DateTime>(s, "SystemPeriodStart"))
			.ToListAsync(Cancellation);
		scopeVersions.Count.ShouldBe(2);
		scopeVersions.ShouldAllBe(static s => s.Properties!["spike"].GetRawText() == """{"k":1}""");
		scopeVersions[0].Resources.ShouldBe(["spike-api"]);
		scopeVersions[1].Resources!.Order(StringComparer.Ordinal).ShouldBe(["spike-api", "spike-api-2"]);

		var resourceId = ((NorseOpenIddictResource)resource).Id;
		var resourceVersions = await context.Set<NorseOpenIddictResource>().TemporalAll()
			.Where(r => r.Id == resourceId)
			.OrderBy(static r => EF.Property<DateTime>(r, "SystemPeriodStart"))
			.ToListAsync(Cancellation);
		resourceVersions.Count.ShouldBe(2);
		resourceVersions.ShouldAllBe(static r => r.Properties!["spike"].GetRawText() == """{"k":1}""");
		resourceVersions.ShouldAllBe(static r => r.DisplayNames!.Single().Value == "Spike");
		resourceVersions[0].Description.ShouldBeNull();
		resourceVersions[1].Description.ShouldBe("updated");
	}

	/// <summary>A table's GENERATED ALWAYS period columns, each with its role and whether it is HIDDEN.</summary>
	static Task<List<string>> PeriodColumnsAsync(DbContext context, string table)
	{
		var qualified = $"dbo.{table}";
		return context.Database.SqlQuery<string>(
			$"""
			SELECT CONCAT(name, N' ', generated_always_type_desc COLLATE DATABASE_DEFAULT, N' hidden=', is_hidden) AS Value
			FROM sys.columns
			WHERE object_id = OBJECT_ID({qualified}) AND generated_always_type <> 0
			ORDER BY name
			""").ToListAsync(Cancellation);
	}
}
