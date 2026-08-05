using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.PostgreSQL;
using Norse.Persistence.EntityFramework.SqlServer;

namespace Norse.Identity.EntityFramework.Tests;

/// <summary>
/// Which identity tables are system-versioned, pinned from both sides. Himinbjörg#47 open question 4,
/// ruled 2026-08-05: temporal marks the durable identity and authorization record; secret stores,
/// counters, and prunable runtime state stay non-temporal, and secret material never archives to
/// history (rotation and destruction must destroy). The scope is a ruling, not an implementation
/// detail — adding or dropping a marker without amending that ruling breaks these facts by design.
/// </summary>
public sealed class NorseIdentityTemporalModelTests
{
	const string DatabaseName = "norse_identity_temporal_model_test";

	// Same shape as NorseIdentityModelTests: build the model per provider the way the design-time
	// factories do, so the SQL Server binding's temporal realization hook is actually in play.
	static IModel BuildModel(INorseEfProvider provider)
	{
		DbContextOptionsBuilder<NorseIdentityDbContext> builder = new();
		builder.ApplyNorseProviderOptions(provider, provider.DesignTimePlaceholderConnectionString(DatabaseName), null);
		using NorseIdentityDbContext context = new(builder.Options);
		return context.Model;
	}

	static readonly Lazy<IModel> _sqlServerModel = new(() => BuildModel(NorseSqlServerEfProvider.Instance));
	static readonly Lazy<IModel> _postgresModel = new(() => BuildModel(NorsePostgresEfProvider.Instance));

	static IModel SqlServerModel => _sqlServerModel.Value;
	static IModel PostgresModel => _postgresModel.Value;

	/// <summary>The eight ruled temporal entities, in the order the ruling lists them.</summary>
	static readonly Type[] _temporalEntities =
	[
		typeof(NorseUser), typeof(NorseRole), typeof(NorseUserClaim), typeof(NorseRoleClaim),
		typeof(NorseUserRole), typeof(NorseUserLogin), typeof(NorseOpenIddictApplication),
		typeof(NorseOpenIddictScope)
	];

	[Theory]
	[InlineData(typeof(NorseUser), "users")]
	[InlineData(typeof(NorseRole), "roles")]
	[InlineData(typeof(NorseUserClaim), "user_claims")]
	[InlineData(typeof(NorseRoleClaim), "role_claims")]
	[InlineData(typeof(NorseUserRole), "user_roles")]
	// Deliberately in: a third-party link that existed and was later disconnected is identity record
	// worth keeping.
	[InlineData(typeof(NorseUserLogin), "user_logins")]
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
	// Crypto-shred law: a temporal DELETE would preserve the wrapped DEK in history and make erasure
	// reversible.
	[InlineData(typeof(SubjectKey))]
	void Secret_stores_counters_and_prunable_runtime_state_stay_non_temporal(Type entityType)
	{
		foreach (var model in new[] { PostgresModel, SqlServerModel })
			model.FindEntityType(entityType)!.FindAnnotation(NorseAnnotationNames.Temporal).ShouldBeNull();
	}

	[Fact]
	void Exactly_the_eight_ruled_entities_carry_the_stamp_and_nothing_else()
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
	void Sql_server_realizes_the_stamp_as_engine_native_system_versioning()
	{
		// Proof the realization hook reaches this context at all: NorseIdentityDbContext replicates
		// NorseDbContext's conventions rather than inheriting them, so it has to read the hook off its own
		// options and hand it to NorseModelConventions.Apply. Postgres supplies no hook -- it realizes
		// temporality in migration SQL generation, never in the model -- so SQL Server is where a missing
		// wire shows.
		foreach (var entityType in _temporalEntities)
			SqlServerModel.FindEntityType(entityType)!.IsTemporal().ShouldBeTrue();
	}
}
