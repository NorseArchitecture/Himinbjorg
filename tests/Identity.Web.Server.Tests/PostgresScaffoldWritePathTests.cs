namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="ScaffoldWritePathSuite" /> over <c>postgres:19rc1</c>.</summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresScaffoldWritePathTests(PostgresIdentityFixture fixture) : ScaffoldWritePathSuite(fixture);
