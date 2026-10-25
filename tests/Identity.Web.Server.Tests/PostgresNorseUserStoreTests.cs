using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="NorseUserStoreSuite" /> over <c>postgres:19rc1</c>.</summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresNorseUserStoreTests(PostgresIdentityFixture fixture) : NorseUserStoreSuite(fixture)
{
	protected override Task<long> UserVersionsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
				$"""SELECT count(*) AS "Value" FROM public.users_history WHERE id = {userId}""")
			.SingleAsync(Cancellation);

	protected override Task<List<string>> ClaimHistoryValuesAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<string>(
				$"""SELECT claim_value AS "Value" FROM public.user_claims_history WHERE user_id = {userId}""")
			.ToListAsync(Cancellation);
}
