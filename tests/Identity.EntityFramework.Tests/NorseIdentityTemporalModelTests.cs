using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.PostgreSQL;
using Norse.Persistence.EntityFramework.SqlServer;

namespace Norse.Identity.EntityFramework.Tests;

/// <summary>
///     Which identity tables are system-versioned, pinned from both sides. Himinbjörg#47 open question 4,
///     ruled 2026-08-05: temporal marks the durable identity and authorization record; secret stores,
///     counters, and prunable runtime state stay non-temporal, and secret material never archives to
///     history (rotation and destruction must destroy). The scope is a ruling, not an implementation
///     detail — adding or dropping a marker without amending that ruling breaks these facts by design.
/// </summary>
public sealed class NorseIdentityTemporalModelTests
{
	const string DatabaseName = "norse_identity_temporal_model_test";

	static readonly Lazy<IModel> _sqlServerModel = new(() => BuildModel(NorseSqlServerEfProvider.Instance));
	static readonly Lazy<IModel> _postgresModel = new(() => BuildModel(NorsePostgresEfProvider.Instance));

	/// <summary>
	///     The seven ruled temporal entities, in the order the ruling lists them (2026-10-24 explicit-writes spec
	///     §3.1 took <see cref="NorseUserLogin" /> out).
	/// </summary>
	static readonly Type[] _temporalEntities =
	[
		typeof(NorseUser), typeof(NorseRole), typeof(NorseUserClaim), typeof(NorseRoleClaim),
		typeof(NorseUserRole), typeof(NorseOpenIddictApplication), typeof(NorseOpenIddictScope)
	];

	static IModel SqlServerModel => _sqlServerModel.Value;
	static IModel PostgresModel => _postgresModel.Value;

	// Same shape as NorseIdentityModelTests: build the model per provider the way the design-time
	// factories do, so the SQL Server binding's temporal realization hook is actually in play.
	static IModel BuildModel(INorseEfProvider provider)
	{
		DbContextOptionsBuilder<NorseIdentityDbContext> builder = new();
		builder.ApplyNorseProviderOptions(provider, provider.DesignTimePlaceholderConnectionString(DatabaseName), null);
		using NorseIdentityDbContext context = new(builder.Options);
		return context.Model;
	}

	[Theory]
	[InlineData(typeof(NorseUser), "users")]
	[InlineData(typeof(NorseRole), "roles")]
	[InlineData(typeof(NorseUserClaim), "user_claims")]
	[InlineData(typeof(NorseRoleClaim), "role_claims")]
	[InlineData(typeof(NorseUserRole), "user_roles")]
	[InlineData(typeof(NorseOpenIddictApplication), "applications")]
	[InlineData(typeof(NorseOpenIddictScope), "scopes")]
	void The_durable_identity_and_authorization_record_carries_the_temporal_stamp(Type entityType, string table)
	{
		foreach (var model in new[] { PostgresModel, SqlServerModel })
			model.FindEntityType(entityType)!
				.FindAnnotation(NorseAnnotationNames.Temporal).ShouldNotBeNull().Value.ShouldBe(true);

		// The root table name rides along per case, so the ruling's table list stays greppable from the
		// entity list and a silent ToTable(...) change can't quietly re-point a ruled mark.
		PostgresModel.FindEntityType(entityType)!.GetTableName().ShouldBe(table);
	}

	[Theory]
	// Secret store: TOTP authenticator keys and recovery codes consumed by UPDATE -- superseded secrets
	// must not survive in history.
	[InlineData(typeof(NorseUserToken))]
	// WebAuthn SignCount updates every sign-in -- lockout-churn shape, a future split-off, not this pass.
	[InlineData(typeof(NorseUserPasskey))]
	// Runtime consent state, bulk-pruned -- history would be landfill.
	[InlineData(typeof(NorseOpenIddictAuthorization))]
	// One-time codes and refresh tokens, redeemed by UPDATE and pruned.
	[InlineData(typeof(NorseOpenIddictToken))]
	// External-login links: out of the temporal set by the 2026-10-24 explicit-writes spec §3.1, which
	// supersedes the 2026-08-05 ruling that kept a disconnected link as identity record.
	[InlineData(typeof(NorseUserLogin))]
	// Crypto-shred law: a temporal DELETE would preserve the wrapped DEK in history and make erasure
	// reversible.
	[InlineData(typeof(SubjectKey))]
	void Secret_stores_counters_and_prunable_runtime_state_stay_non_temporal(Type entityType)
	{
		foreach (var model in new[] { PostgresModel, SqlServerModel })
			model.FindEntityType(entityType)!.FindAnnotation(NorseAnnotationNames.Temporal).ShouldBeNull();
	}

	[Fact]
	void Exactly_the_seven_ruled_entities_carry_the_stamp_and_nothing_else()
	{
		// The per-case theories above pin the named entities; this one closes the model, so a schema
		// addition that arrives already marked has to pass through the ruling to get here.
		foreach (var model in new[] { PostgresModel, SqlServerModel })
			model.GetEntityTypes()
				.Where(entity => entity.FindAnnotation(NorseAnnotationNames.Temporal) is not null)
				.Select(entity => entity.ClrType)
				.OrderBy(type => type.Name, StringComparer.Ordinal)
				.ShouldBe(_temporalEntities.OrderBy(type => type.Name, StringComparer.Ordinal));
	}

	[Fact]
	void Sql_server_versions_only_the_users_principal_table_and_keeps_every_other_temporal_entity_ef_native()
	{
		// Proof the realization hook reaches this context at all: NorseIdentityDbContext replicates
		// NorseDbContext's conventions rather than inheriting them, so it has to read the hook off its own
		// options and hand it to NorseModelConventions.Apply. Postgres supplies no hook -- it realizes
		// temporality in migration SQL generation, never in the model -- so SQL Server is where a missing
		// wire shows.
		foreach (var entityType in _temporalEntities.Where(static type => type != typeof(NorseUser)))
			SqlServerModel.FindEntityType(entityType)!.IsTemporal().ShouldBeTrue();

		// NorseUser is entity-split (UserCredentials), and EF can't scope SQL Server temporality per fragment
		// (dotnet/efcore#26457), so it opts in to TemporalOnPrincipalTableOnly(): deliberately not
		// EF-temporal, versioned engine-natively on the principal table only. Spec §6.1.
		SqlServerModel.FindEntityType(typeof(NorseUser))!.IsTemporal().ShouldBeFalse();

		DbContextOptionsBuilder<NorseIdentityDbContext> builder = new();
		var provider = NorseSqlServerEfProvider.Instance;
		builder.ApplyNorseProviderOptions(provider, provider.DesignTimePlaceholderConnectionString(DatabaseName), null);
		using NorseIdentityDbContext context = new(builder.Options);

		var tables = context.GetService<IDesignTimeModel>().Model.GetRelationalModel().Tables.ToList();
		tables.Single(static table => table.Name == "Users")
			.FindAnnotation(NorseAnnotationNames.TemporalPrincipalTableOnly).ShouldNotBeNull().Value.ShouldBe(true);
		tables.Where(static table => table.FindAnnotation(NorseAnnotationNames.TemporalPrincipalTableOnly) is not null)
			.Select(static table => table.Name)
			.ShouldBe(["Users"]);

		var script = context.Database.GenerateCreateScript();
		var users = CreateTableStatement(script, "Users");
		users.ShouldContain("[SystemPeriodStart] datetime2 GENERATED ALWAYS AS ROW START HIDDEN NOT NULL");
		users.ShouldContain("[SystemPeriodEnd] datetime2 GENERATED ALWAYS AS ROW END HIDDEN NOT NULL");
		users.ShouldContain("PERIOD FOR SYSTEM_TIME ([SystemPeriodStart], [SystemPeriodEnd])");
		users.ShouldContain("WITH (SYSTEM_VERSIONING = ON (HISTORY_TABLE = [dbo].[UsersHistory]))");

		// The fragment carries the credential churn and the lookup hashes, and is never versioned.
		var credentials = CreateTableStatement(script, "UserCredentials");
		credentials.ShouldNotContain("SYSTEM_VERSIONING");
		credentials.ShouldNotContain("PERIOD FOR");
		credentials.ShouldNotContain("HIDDEN");
		script.ShouldNotContain("[UserCredentialsHistory]");
	}

	// From "CREATE TABLE [name] (" up to the statement terminator EF's SQL Server generator writes.
	static string CreateTableStatement(string script, string table)
	{
		var start = script.IndexOf($"CREATE TABLE [{table}] (", StringComparison.Ordinal);
		start.ShouldBeGreaterThanOrEqualTo(0, $"CREATE TABLE [{table}] should have been emitted");
		var end = script.IndexOf(");", start, StringComparison.Ordinal);
		end.ShouldBeGreaterThan(start);
		return script[start..(end + 2)];
	}
}
