using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="EmailIsUserNameSuite" /> over <c>postgres:19rc1</c>.</summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresEmailIsUserNameTests(PostgresIdentityFixture fixture) : EmailIsUserNameSuite(fixture)
{
	protected override Task<long> UserVersionsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
				$"""SELECT count(*) AS "Value" FROM public.users_history WHERE id = {userId}""")
			.SingleAsync(Cancellation);
}
