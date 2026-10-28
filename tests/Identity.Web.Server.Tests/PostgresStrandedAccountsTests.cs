using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Verification;

namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="StrandedAccountsSuite" /> over <c>postgres:19rc1</c>.</summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresStrandedAccountsTests(PostgresIdentityFixture fixture) : StrandedAccountsSuite(fixture)
{
	protected override Task SeedStrandedAsync(NorseIdentityDbContext context, Guid id)
	{
		var name = $"stranded-{id:N}";
		var stamp = Guid.NewGuid().ToString("N");
		return context.Database.ExecuteSqlAsync(
			$"""
			INSERT INTO users (id, user_name, email_confirmed, concurrency_stamp, phone_number_confirmed, two_factor_enabled, lockout_enabled)
			VALUES ({id}, {name}, false, {Guid.NewGuid()}, false, false, false);
			INSERT INTO user_credentials (id, security_stamp, normalized_user_name, normalized_email, access_failed_count)
			VALUES ({id}, {stamp}, {name}, {name}, 0)
			""", Cancellation);
	}

	protected override Task DeleteCursorAsync(NorseIdentityDbContext context) =>
		context.Database.ExecuteSqlAsync(
			$"DELETE FROM verification_cursors WHERE name = {StrandedAccountsQuery.CursorName}", Cancellation);

	protected override Task DeleteUserAsync(NorseIdentityDbContext context, Guid id) =>
		context.Database.ExecuteSqlAsync($"DELETE FROM users WHERE id = {id}", Cancellation);
}
