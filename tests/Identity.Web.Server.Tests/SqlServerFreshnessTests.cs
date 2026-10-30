namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="FreshnessSuite" /> over SQL Server 2025.</summary>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerFreshnessTests(SqlServerIdentityFixture fixture) : FreshnessSuite(fixture)
{
	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;
}
