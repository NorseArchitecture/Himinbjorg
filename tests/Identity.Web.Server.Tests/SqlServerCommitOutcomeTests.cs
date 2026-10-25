namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="CommitOutcomeSuite" /> over SQL Server 2025.</summary>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerCommitOutcomeTests(SqlServerIdentityFixture fixture) : CommitOutcomeSuite(fixture)
{
	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;
}
