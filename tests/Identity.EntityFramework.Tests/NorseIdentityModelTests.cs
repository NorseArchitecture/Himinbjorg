using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.PostgreSQL;
using Norse.Persistence.EntityFramework.SqlServer;

namespace Norse.Identity.EntityFramework.Tests;

public sealed class NorseIdentityModelTests
{
	const string DatabaseName = "norse_identity_model_test";

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

	static readonly Lazy<IModel> _sqlServerModel = new(() => BuildModel(NorseSqlServerEfProvider.Instance));
	static readonly Lazy<IModel> _postgresModel = new(() => BuildModel(NorsePostgresEfProvider.Instance));

	static IModel SqlServerModel => _sqlServerModel.Value;
	static IModel PostgresModel => _postgresModel.Value;

	// Build the model per provider the way the design-time factories do; reuse any existing
	// model-building helper in this test project.
	[Fact]
	void Normalized_user_name_is_nullable_and_its_unique_index_is_filtered_on_sql_server()
	{
		var entity = SqlServerModel.FindEntityType(typeof(NorseUser))!;
		entity.FindProperty(nameof(NorseUser.NormalizedUserName))!.IsNullable.ShouldBeTrue();
		var index = entity.GetIndexes().Single(i =>
			i.Properties.Single().Name == nameof(NorseUser.NormalizedUserName));
		index.IsUnique.ShouldBeTrue();
		index.GetFilter().ShouldBe("[NormalizedUserName] IS NOT NULL");
	}

	[Fact]
	void Normalized_user_name_unique_index_is_unfiltered_on_postgres()
	{
		var entity = PostgresModel.FindEntityType(typeof(NorseUser))!;
		var index = entity.GetIndexes().Single(i =>
			i.Properties.Single().Name == nameof(NorseUser.NormalizedUserName));
		index.IsUnique.ShouldBeTrue();
		index.GetFilter().ShouldBeNull();
	}

	[Fact]
	void Normalized_email_index_stays_non_unique_on_both_providers()
	{
		// The existing config indexes NormalizedEmail non-uniquely — nullable hashes coexist freely.
		// If this index is EVER made unique, it needs the identical filtered treatment as
		// NormalizedUserName or the second shred-ever violates it on SQL Server. This test is the
		// tripwire that forces that conversation.
		foreach (var model in new[] { SqlServerModel, PostgresModel })
		{
			var index = model.FindEntityType(typeof(NorseUser))!.GetIndexes()
				.Single(i => i.Properties.Single().Name == nameof(NorseUser.NormalizedEmail));
			index.IsUnique.ShouldBeFalse();
		}
	}

	[Fact]
	void User_name_stays_required()
	{
		SqlServerModel.FindEntityType(typeof(NorseUser))!
			.FindProperty(nameof(NorseUser.UserName))!.IsNullable.ShouldBeFalse();
	}

	[Fact]
	void Subject_key_entity_exists_with_the_declared_shape()
	{
		var entity = SqlServerModel.FindEntityType(typeof(SubjectKey))!;
		entity.FindPrimaryKey()!.Properties.Single().Name.ShouldBe(nameof(SubjectKey.SubjectId));
		entity.FindProperty(nameof(SubjectKey.WrappedKey))!.GetMaxLength().ShouldBe(64);
		entity.FindProperty(nameof(SubjectKey.WrappingKeyId))!.GetMaxLength().ShouldBe(128);
	}
}
