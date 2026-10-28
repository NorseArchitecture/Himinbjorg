using System.Runtime.InteropServices;
using DotNet.Testcontainers.Containers;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;
using Norse.Identity.Migrations.SqlServer;
using Norse.Persistence.EntityFramework;
using Norse.Persistence.EntityFramework.SqlServer;
using Testcontainers.MsSql;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The real-SQL Server twin of <see cref="PostgresIdentityFixture" />: the same <see cref="IdentityFixture" />
///     API over <c>mcr.microsoft.com/mssql/server:2025-latest</c>, migrated through the checked-in SQL Server
///     <c>InitialCreate</c>. Pinned to 2025 because <see cref="NorseSqlServerEfProvider" /> forces compatibility
///     level 170 and the passkey payload is native <c>json</c>; both are asserted at startup. The guard and the
///     narrow catch are Urðarbrunnr's <c>SqlServerContainerFixture</c> (plan Global Constraints, ruled 2026-10-25).
/// </summary>
public sealed class SqlServerIdentityFixture : IdentityFixture
{
	// SQL Server 2025 reports ProductMajorVersion 17.
	const int EngineFloor = 17;

	readonly MsSqlContainer _container = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2025-latest").Build();

	/// <summary>
	///     SQL Server's Linux image is x86_64-only, so an arm64 host emulates it, and the emulator decides
	///     everything. Windows on ARM runs it under qemu, where the 2025 image segfaults; that host alone is
	///     excluded. Apple silicon runs it under Rosetta and is supported; x86_64 CI needs neither. Checked
	///     before <c>StartAsync</c>, so an excluded host never pulls the image only to watch it die.
	/// </summary>
	public static bool IsSupportedArchitecture { get; } =
		!(OperatingSystem.IsWindows() && RuntimeInformation.ProcessArchitecture == Architecture.Arm64);

	/// <summary>The <c>[Fact(SkipUnless = …)]</c> pre-flight gate: a daemon answers, on a supported host.</summary>
	public static bool IsTestable =>
		DockerAvailability.IsAvailable && IsSupportedArchitecture;

	/// <inheritdoc />
	protected override INorseEfProvider Provider => NorseSqlServerEfProvider.Instance;

	/// <inheritdoc />
	protected override string MigrationsAssemblyName =>
		typeof(NorseIdentityDbContextFactory).Assembly.GetName().Name!;

	/// <inheritdoc />
	protected override async Task<string?> StartDatabaseAsync()
	{
		if (!IsTestable)
		{
			MarkUnavailable(IsSupportedArchitecture ?
				"No Docker daemon answered." :
				"SQL Server's Linux image is x86_64-only and segfaults under qemu emulation on Windows on ARM.");
			return null;
		}

		try
		{
			await _container.StartAsync();
		}
		// Two named types, never a bare catch (Exception): ContainerNotRunningException is Testcontainers' own
		// signal that the container died before becoming ready (the qemu segfault's shape), and
		// NotSupportedException is what Testcontainers.MsSql's sqlcmd readiness probe throws when the container
		// died before the probe could find the binary. Anything else is a real bug and propagates.
		catch (Exception ex) when (ex is ContainerNotRunningException or NotSupportedException)
		{
			MarkUnavailable(ex.Message);
			return null;
		}

		var masterConnectionString = _container.GetConnectionString();
		// The engine floor, asserted before the migration: a pre-2025 engine would accept most DDL and then
		// fail the native json type far from here.
		var majorVersion = await EngineMajorVersionAsync(masterConnectionString);
		if (majorVersion < EngineFloor)
			throw new InvalidOperationException(
				$"SQL Server {majorVersion} is below the SQL Server 2025 floor (major version {EngineFloor}).");

		// The migration creates the database itself, exactly as the migrations service does.
		return new SqlConnectionStringBuilder(masterConnectionString) { InitialCatalog = "norse_identity" }
			.ConnectionString;
	}

	/// <inheritdoc />
	protected override async Task VerifySchemaAsync(NorseIdentityDbContext context)
	{
		// The complete migration applied, down to its last table: the passkey payload is native json, which
		// only a 2025 engine at compatibility level 170 creates.
		var passkeyDataType = await context.Database.SqlQuery<string>(
				$"""
				SELECT t.name AS Value
				FROM sys.columns c JOIN sys.types t ON t.user_type_id = c.user_type_id
				WHERE c.object_id = OBJECT_ID(N'dbo.UserPasskeys') AND c.name = N'Data'
				""")
			.SingleOrDefaultAsync(CancellationToken.None);
		if (passkeyDataType != "json")
			throw new InvalidOperationException(
				$"UserPasskeys.Data is '{passkeyDataType ?? "missing"}', not native json: the identity migration did not apply completely.");
	}

	/// <inheritdoc />
	protected override string ConnectionStringFor(string connectionString, string database) =>
		new SqlConnectionStringBuilder(connectionString) { InitialCatalog = database }.ConnectionString;

	/// <inheritdoc />
	protected override string DropDatabaseSql(string database) =>
		$"ALTER DATABASE [{database}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{database}]";

	/// <inheritdoc />
	protected override Task<string> ReadRawEmailAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database
			.SqlQuery<string>($"SELECT Email AS Value FROM dbo.Users WHERE Id = {userId}")
			.SingleAsync(CancellationToken.None);

	/// <inheritdoc />
	protected override Task<string> ReadRawNormalizedEmailAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database
			.SqlQuery<string>($"SELECT NormalizedEmail AS Value FROM dbo.UserCredentials WHERE Id = {userId}")
			.SingleAsync(CancellationToken.None);

	// Unconditional: a container that started and then failed the engine floor must not outlive the run, and
	// disposing one that never started is a no-op.
	/// <inheritdoc />
	protected override ValueTask DisposeDatabaseAsync() =>
		_container.DisposeAsync();

	static async Task<int> EngineMajorVersionAsync(string connectionString)
	{
		await using SqlConnection connection = new(connectionString);
		await connection.OpenAsync();
		await using SqlCommand command = new("SELECT CAST(SERVERPROPERTY('ProductMajorVersion') AS int)", connection);
		return await command.ExecuteScalarAsync() is int majorVersion ?
			majorVersion :
			throw new InvalidOperationException("SERVERPROPERTY('ProductMajorVersion') returned no value.");
	}
}
