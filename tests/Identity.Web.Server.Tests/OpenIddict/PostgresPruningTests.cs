namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary><see cref="PruningSuite" /> over <c>postgres:19rc1</c>.</summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresPruningTests(PostgresIdentityFixture fixture) : PruningSuite(fixture);
