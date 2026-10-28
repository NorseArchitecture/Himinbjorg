using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="LastSignInMethodSuite" /> over SQL Server 2025.</summary>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerLastSignInMethodTests(SqlServerIdentityFixture fixture) : LastSignInMethodSuite(fixture)
{
	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;

	protected override Task LockCredentialsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<int>($"SELECT 1 AS [Value] FROM [UserCredentials] WITH (UPDLOCK, HOLDLOCK) WHERE [Id] = {userId}")
			.ToListAsync(Cancellation);
}
