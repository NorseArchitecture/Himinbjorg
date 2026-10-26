namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="ErasureServiceSuite" /> over SQL Server 2025.</summary>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerErasureServiceTests(SqlServerIdentityFixture fixture) : ErasureServiceSuite(fixture)
{
	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;

	protected override string UsersHistoryTable => "UsersHistory";

	// SystemPeriodStart and SystemPeriodEnd, each a datetime2.
	protected override Type PeriodType => typeof(DateTime);
}
