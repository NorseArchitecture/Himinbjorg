using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;
using Norse.Identity.Migrations.PostgreSQL;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.PostgreSQL;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The real-Postgres <see cref="IdentityFixture" />: a <c>postgres:19rc1</c> container migrated through the
///     checked-in Postgres <c>InitialCreate</c>. Shared through <see cref="PostgresTestGroup" />; see the base's
///     remark for why exactly one instance may ever exist per process.
/// </summary>
public sealed class PostgresIdentityFixture : IdentityFixture
{
	readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:19rc1")
		.WithDatabase("norse_identity")
		.Build();

	/// <inheritdoc />
	protected override INorseEfProvider Provider => NorsePostgresEfProvider.Instance;

	/// <inheritdoc />
	protected override string MigrationsAssemblyName =>
		typeof(NorseIdentityDbContextFactory).Assembly.GetName().Name!;

	/// <inheritdoc />
	protected override async Task<string?> StartDatabaseAsync()
	{
		await _container.StartAsync();
		return _container.GetConnectionString();
	}

	/// <inheritdoc />
	protected override string ConnectionStringFor(string connectionString, string database) =>
		new NpgsqlConnectionStringBuilder(connectionString) { Database = database }.ConnectionString;

	/// <inheritdoc />
	protected override string DropDatabaseSql(string database) =>
		$"DROP DATABASE {database} WITH (FORCE)";

	/// <inheritdoc />
	protected override Task<string> ReadRawEmailAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database
			.SqlQuery<string>($"""SELECT email AS "Value" FROM users WHERE id = {userId}""")
			.SingleAsync(CancellationToken.None);

	/// <inheritdoc />
	protected override Task<string> ReadRawNormalizedEmailAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database
			.SqlQuery<string>($"""SELECT normalized_email AS "Value" FROM user_credentials WHERE id = {userId}""")
			.SingleAsync(CancellationToken.None);

	/// <inheritdoc />
	protected override ValueTask DisposeDatabaseAsync() =>
		_container.DisposeAsync();
}
