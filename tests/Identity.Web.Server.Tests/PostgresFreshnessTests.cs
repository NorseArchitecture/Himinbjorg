namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="FreshnessSuite" /> over <c>postgres:19rc1</c>.</summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresFreshnessTests(PostgresIdentityFixture fixture) : FreshnessSuite(fixture);
