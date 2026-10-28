using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="PasskeySignInWritePathSuite" /> over <c>postgres:19rc1</c>.</summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresPasskeySignInWritePathTests(PostgresIdentityFixture fixture) : PasskeySignInWritePathSuite(fixture)
{
	protected override Task<long> UserVersionsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
				$"""SELECT count(*) AS "Value" FROM public.users_history WHERE id = {userId}""")
			.SingleAsync(Cancellation);
}
