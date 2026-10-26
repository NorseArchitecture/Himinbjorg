using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.PostgreSQL;
using Norse.Persistence.EntityFramework.SqlServer;

namespace Norse.Identity.EntityFramework.Tests;

public sealed class NorseIdentityModelTests
{
	const string DatabaseName = "norse_identity_model_test";

	static readonly Lazy<IModel> _sqlServerModel = new(() => BuildModel(NorseSqlServerEfProvider.Instance));
	static readonly Lazy<IModel> _postgresModel = new(() => BuildModel(NorsePostgresEfProvider.Instance));

	static readonly Lazy<IRelationalModel> _sqlServerTables = new(() => BuildDesignTimeModel(NorseSqlServerEfProvider.Instance));
	static readonly Lazy<IRelationalModel> _postgresTables = new(() => BuildDesignTimeModel(NorsePostgresEfProvider.Instance));

	static IModel SqlServerModel => _sqlServerModel.Value;
	static IModel PostgresModel => _postgresModel.Value;

	// Build the model per provider the way the design-time factories do (ApplyNorseProviderOptions
	// against the real provider binding) -- notably the SQL Server compatibility-level-170 floor,
	// without which ComplexProperty<T>().ToJson() (the passkey Data mapping) does not compose.
	static IModel BuildModel(INorseEfProvider provider)
	{
		DbContextOptionsBuilder<NorseIdentityDbContext> builder = new();
		builder.ApplyNorseProviderOptions(provider, provider.DesignTimePlaceholderConnectionString(DatabaseName), null);
		using NorseIdentityDbContext context = new(builder.Options);
		return context.Model;
	}

	// The design-time model's relational model carries every table's columns, indexes, check constraints and
	// foreign-key constraints, including the fragment's.
	static IRelationalModel BuildDesignTimeModel(INorseEfProvider provider)
	{
		DbContextOptionsBuilder<NorseIdentityDbContext> builder = new();
		builder.ApplyNorseProviderOptions(provider, provider.DesignTimePlaceholderConnectionString(DatabaseName), null);
		using NorseIdentityDbContext context = new(builder.Options);
		return context.GetService<IDesignTimeModel>().Model.GetRelationalModel();
	}

	static ITable Table(bool sqlServer, string name) =>
		(sqlServer ?
			_sqlServerTables.Value :
			_postgresTables.Value).Tables.Single(table => table.Name == name);

	// The user_credentials fragment (2026-10-24 explicit-writes spec §3): the non-temporal credential and lookup
	// columns, split off users so credential churn never mints a users history row.
	[Theory]
	[InlineData(true, "UserCredentials")]
	[InlineData(false, "user_credentials")]
	void The_credentials_fragment_carries_exactly_the_six_credential_and_lookup_columns(bool sqlServer, string table)
	{
		var fragment = Table(sqlServer, table);

		fragment.Columns
			.SelectMany(static column => column.PropertyMappings)
			.Select(static mapping => mapping.Property.Name)
			.Distinct()
			.Order(StringComparer.Ordinal)
			.ShouldBe(new[]
			{
				nameof(NorseUser.AccessFailedCount), nameof(NorseUser.Id), nameof(NorseUser.LockoutEnd),
				nameof(NorseUser.NormalizedEmail), nameof(NorseUser.NormalizedUserName),
				nameof(NorseUser.PasswordHash), nameof(NorseUser.SecurityStamp)
			}.Order(StringComparer.Ordinal));
	}

	[Theory]
	[InlineData(nameof(NorseUser.NormalizedEmail))]
	[InlineData(nameof(NorseUser.NormalizedUserName))]
	void Both_lookup_hashes_are_required(string property)
	{
		foreach (var model in new[] { SqlServerModel, PostgresModel })
			model.FindEntityType(typeof(NorseUser))!.FindProperty(property)!.IsNullable.ShouldBeFalse();
	}

	[Theory]
	[InlineData(true, "UserCredentials", "NormalizedUserName")]
	[InlineData(false, "user_credentials", "normalized_user_name")]
	void The_normalized_user_name_unique_index_lives_on_the_fragment_unfiltered(bool sqlServer, string table,
		string column)
	{
		var index = Table(sqlServer, table).Indexes.Single(static i => i.IsUnique);

		index.Columns.Select(static c => c.Name).ShouldBe([column]);
		index.Filter.ShouldBeNull();
		Table(sqlServer, sqlServer ? "Users" : "users").Indexes
			.ShouldNotContain(static i => i.Columns.Any(static c => c.Name.Contains("ormalized", StringComparison.Ordinal)));
	}

	// EF can't declare a CHECK on a split fragment, so it rides Urðarbrunnr's fragment seam: an annotation the
	// provider binding projects onto the fragment's table, and onto no other.
	[Theory]
	[InlineData(true, "UserCredentials", "Users", "CK_UserCredentials_EmailIsUserName",
		"[NormalizedEmail] = [NormalizedUserName]")]
	[InlineData(false, "user_credentials", "users", "ck_user_credentials_email_is_user_name",
		"normalized_email = normalized_user_name")]
	void The_fragment_checks_that_the_email_hash_equals_the_user_name_hash(bool sqlServer, string table,
		string principal, string name, string sql)
	{
		FragmentCheckConstraints(Table(sqlServer, table)).ShouldBe([(name, sql)]);
		FragmentCheckConstraints(Table(sqlServer, principal)).ShouldBeEmpty();
		Table(sqlServer, principal).CheckConstraints.ShouldBeEmpty();
	}

	static (string Name, string? Sql)[] FragmentCheckConstraints(ITable table) =>
	[
		.. table.GetAnnotations()
			.Where(static annotation =>
				annotation.Name.StartsWith(NorseAnnotationNames.FragmentCheckConstraintPrefix, StringComparison.Ordinal))
			.Select(static annotation =>
				(annotation.Name[NorseAnnotationNames.FragmentCheckConstraintPrefix.Length..], annotation.Value as string))
	];

	[Fact]
	void The_fragment_foreign_key_cascades_on_both_providers()
	{
		foreach (var (sqlServer, table) in new[] { (true, "UserCredentials"), (false, "user_credentials") })
			Table(sqlServer, table).ForeignKeyConstraints.Single().OnDeleteAction
				.ShouldBe(ReferentialAction.Cascade);
	}

	[Theory]
	[InlineData(true, "ISNULL(CAST(HASHBYTES('SHA2_256', [ClaimValue]) AS binary(32)), 0x)")]
	[InlineData(false, "norse_utf8_sha256(claim_value)")]
	void The_claim_value_hash_is_a_required_stored_shadow_hash(bool sqlServer, string computedSql)
	{
		var claims = (sqlServer ?
			SqlServerModel :
			PostgresModel).FindEntityType(typeof(NorseUserClaim))!;
		var hash = claims.FindProperty("ClaimValueHash").ShouldNotBeNull();

		hash.IsShadowProperty().ShouldBeTrue("a CLR member would change the drop-in IdentityUserClaim shape");
		hash.ClrType.ShouldBe(typeof(byte[]));
		hash.IsNullable.ShouldBeFalse("left nullable, EF filters the unique index and SQL Server refuses that");
		hash.GetComputedColumnSql().ShouldBe(computedSql);
		hash.GetIsStored().ShouldBe(true);
	}

	[Theory]
	[InlineData(true, "UserClaims", "UserId,ClaimType,ClaimValueHash")]
	[InlineData(false, "user_claims", "user_id,claim_type,claim_value_hash")]
	void Claims_are_a_set_under_an_unfiltered_unique_index_on_the_hash(bool sqlServer, string table, string columns)
	{
		var index = Table(sqlServer, table).Indexes.Single(static i => i.IsUnique);

		string.Join(',', index.Columns.Select(static c => c.Name)).ShouldBe(columns);
		index.Filter.ShouldBeNull();
	}

	[Fact]
	void Claim_value_is_required()
	{
		foreach (var model in new[] { SqlServerModel, PostgresModel })
			model.FindEntityType(typeof(NorseUserClaim))!
				.FindProperty(nameof(NorseUserClaim.ClaimValue))!.IsNullable.ShouldBeFalse();
	}

	[Fact]
	void User_name_stays_required()
	{
		SqlServerModel.FindEntityType(typeof(NorseUser))!
			.FindProperty(nameof(NorseUser.UserName))!.IsNullable.ShouldBeFalse();
	}

	// The three relationship facts below moved here from NorseUserConfigureTests,
	// NorseRoleConfigureTests and NorseUserRoleConfigureTests (Task 4.2 triage, 2026-10-24). Their
	// Configure methods stopped hand-writing .IsRequired() on the relationships (house rules: EF
	// infers requiredness from the non-nullable Guid FK), and that inference is a convention -- a
	// bare new ModelBuilder() runs none, so it can't observe it. These assert the same thing against
	// the model each provider actually ships.

	[Fact]
	void User_claims_are_required_through_the_User_navigation()
	{
		IModel[] models = [SqlServerModel, PostgresModel];
		foreach (var model in models)
		{
			var fk = model.FindEntityType(typeof(NorseUserClaim))!.GetForeignKeys().Single();

			fk.DependentToPrincipal!.Name.ShouldBe(nameof(NorseUserClaim.User));
			fk.IsRequired.ShouldBeTrue();
		}
	}

	[Fact]
	void Role_claims_are_required_through_the_Role_navigation()
	{
		IModel[] models = [SqlServerModel, PostgresModel];
		foreach (var model in models)
		{
			var fk = model.FindEntityType(typeof(NorseRoleClaim))!.GetForeignKeys().Single();

			fk.DependentToPrincipal!.Name.ShouldBe(nameof(NorseRoleClaim.Role));
			fk.IsRequired.ShouldBeTrue();
		}
	}

	[Fact]
	void User_roles_are_required_through_explicit_User_and_Role_navigations()
	{
		IModel[] models = [SqlServerModel, PostgresModel];
		foreach (var model in models)
		{
			List<IForeignKey> foreignKeys = [.. model.FindEntityType(typeof(NorseUserRole))!.GetForeignKeys()];

			foreignKeys.Count.ShouldBe(2);
			foreignKeys.ShouldContain(fk =>
				fk.DependentToPrincipal!.Name == nameof(NorseUserRole.User) && fk.IsRequired);
			foreignKeys.ShouldContain(fk =>
				fk.DependentToPrincipal!.Name == nameof(NorseUserRole.Role) && fk.IsRequired);
		}
	}

	[Fact]
	void Subject_key_entity_exists_with_the_declared_shape()
	{
		var entity = SqlServerModel.FindEntityType(typeof(SubjectKey))!;
		// Plural, like every sibling table (Users, Roles, ...) -- pinned per provider so a future
		// edit that drops SubjectKey.Configure's ToTable("SubjectKeys") call regresses silently no
		// longer: SQL Server keeps the raw PascalCase name, Postgres rewrites it to snake_case.
		entity.GetTableName().ShouldBe("SubjectKeys");
		entity.FindPrimaryKey()!.Properties.Single().Name.ShouldBe(nameof(SubjectKey.SubjectId));
		entity.FindProperty(nameof(SubjectKey.WrappedKey))!.GetMaxLength().ShouldBe(64);
		entity.FindProperty(nameof(SubjectKey.WrappingKeyId))!.GetMaxLength().ShouldBe(128);

		PostgresModel.FindEntityType(typeof(SubjectKey))!.GetTableName().ShouldBe("subject_keys");
	}
}
