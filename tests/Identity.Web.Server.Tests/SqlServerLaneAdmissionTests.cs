namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="LaneAdmissionSuite" /> over SQL Server 2025.</summary>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerLaneAdmissionTests(SqlServerIdentityFixture fixture) : LaneAdmissionSuite(fixture)
{
	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;
}
