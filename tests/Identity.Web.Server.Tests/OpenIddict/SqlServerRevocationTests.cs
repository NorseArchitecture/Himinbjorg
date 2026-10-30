namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary><see cref="RevocationSuite" /> over SQL Server 2025.</summary>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerRevocationTests(SqlServerIdentityFixture fixture) : RevocationSuite(fixture)
{
	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;
}
