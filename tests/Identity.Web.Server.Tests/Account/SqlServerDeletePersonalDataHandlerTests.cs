namespace Norse.Identity.Web.Server.Tests.Account;

/// <summary><see cref="DeletePersonalDataHandlerSuite" /> over SQL Server 2025.</summary>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerDeletePersonalDataHandlerTests(SqlServerIdentityFixture fixture) : DeletePersonalDataHandlerSuite(fixture)
{
	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;
}
