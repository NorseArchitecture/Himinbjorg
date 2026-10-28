using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Verification;

namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="StrandedAccountsSuite" /> over SQL Server 2025.</summary>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerStrandedAccountsTests(SqlServerIdentityFixture fixture) : StrandedAccountsSuite(fixture)
{
	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;

	protected override Task SeedStrandedAsync(NorseIdentityDbContext context, Guid id)
	{
		var name = $"stranded-{id:N}";
		var stamp = Guid.NewGuid().ToString("N");
		return context.Database.ExecuteSqlAsync(
			$"""
			INSERT INTO [Users] ([Id], [UserName], [EmailConfirmed], [ConcurrencyStamp], [PhoneNumberConfirmed], [TwoFactorEnabled], [LockoutEnabled])
			VALUES ({id}, {name}, 0, {Guid.NewGuid()}, 0, 0, 0);
			INSERT INTO [UserCredentials] ([Id], [SecurityStamp], [NormalizedUserName], [NormalizedEmail], [AccessFailedCount])
			VALUES ({id}, {stamp}, {name}, {name}, 0)
			""", Cancellation);
	}

	protected override Task DeleteCursorAsync(NorseIdentityDbContext context) =>
		context.Database.ExecuteSqlAsync(
			$"DELETE FROM [VerificationCursors] WHERE [Name] = {StrandedAccountsQuery.CursorName}", Cancellation);

	protected override Task DeleteUserAsync(NorseIdentityDbContext context, Guid id) =>
		context.Database.ExecuteSqlAsync($"DELETE FROM [Users] WHERE [Id] = {id}", Cancellation);
}
