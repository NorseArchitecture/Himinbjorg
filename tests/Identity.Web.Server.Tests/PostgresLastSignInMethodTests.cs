using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="LastSignInMethodSuite" /> over <c>postgres:19rc1</c>.</summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresLastSignInMethodTests(PostgresIdentityFixture fixture) : LastSignInMethodSuite(fixture)
{
	protected override Task LockCredentialsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<int>($"""SELECT 1 AS "Value" FROM user_credentials WHERE id = {userId} FOR UPDATE""")
			.ToListAsync(Cancellation);
}
