namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="AuthTimeSuite" /> over SQL Server 2025.</summary>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerAuthTimeTests(SqlServerIdentityFixture fixture) : AuthTimeSuite(fixture)
{
	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;
}
