namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary><see cref="AuthorizeEndpointSuite" /> over SQL Server 2025.</summary>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerAuthorizeEndpointTests(SqlServerIdentityFixture fixture) : AuthorizeEndpointSuite(fixture)
{
	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;
}
