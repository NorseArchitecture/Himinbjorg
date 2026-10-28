using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests.TwoFactor;

/// <summary><see cref="StampRefreshSuite" /> over SQL Server 2025.</summary>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerStampRefreshTests(SqlServerIdentityFixture fixture) : StampRefreshSuite(fixture)
{
	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;

	protected override Task<long> UserVersionsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
				$"SELECT COUNT_BIG(*) AS Value FROM [dbo].[UsersHistory] WHERE [Id] = {userId}")
			.SingleAsync(Cancellation);

	protected override Task<int> RotateStoredSecurityStampAsync(NorseIdentityDbContext context, Guid userId, string stamp,
		CancellationToken cancellationToken) =>
		context.Database.ExecuteSqlAsync(
			$"UPDATE [dbo].[UserCredentials] SET [SecurityStamp] = {stamp} WHERE [Id] = {userId}", cancellationToken);
}
