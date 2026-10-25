using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="NorseUserStoreSuite" /> over SQL Server 2025.</summary>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerNorseUserStoreTests(SqlServerIdentityFixture fixture) : NorseUserStoreSuite(fixture)
{
	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;

	protected override Task<long> UserVersionsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
				$"SELECT COUNT_BIG(*) AS Value FROM [dbo].[UsersHistory] WHERE [Id] = {userId}")
			.SingleAsync(Cancellation);

	protected override Task<List<string>> ClaimHistoryValuesAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<string>(
				$"SELECT [ClaimValue] AS Value FROM [dbo].[UserClaimsHistory] WHERE [UserId] = {userId}")
			.ToListAsync(Cancellation);
}
