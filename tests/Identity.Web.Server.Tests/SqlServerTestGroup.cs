namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     Declares <see cref="SqlServerIdentityFixture" /> as a shared collection fixture -- the SQL Server twin of
///     <see cref="PostgresTestGroup" />, under the same one-instance-per-provider law (see
///     <see cref="IdentityFixture" />'s remark).
/// </summary>
[CollectionDefinition(Name)]
public sealed class SqlServerTestGroup : ICollectionFixture<SqlServerIdentityFixture>
{
	/// <summary>The collection name every real-SQL Server test class opts into via <c>[Collection(Name)]</c>.</summary>
	public const string Name = "SqlServer";
}
