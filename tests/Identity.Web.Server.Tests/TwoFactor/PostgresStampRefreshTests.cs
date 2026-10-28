using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests.TwoFactor;

/// <summary><see cref="StampRefreshSuite" /> over <c>postgres:19rc1</c>.</summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresStampRefreshTests(PostgresIdentityFixture fixture) : StampRefreshSuite(fixture)
{
	protected override Task<long> UserVersionsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
				$"""SELECT count(*) AS "Value" FROM public.users_history WHERE id = {userId}""")
			.SingleAsync(Cancellation);

	protected override Task<int> RotateStoredSecurityStampAsync(NorseIdentityDbContext context, Guid userId, string stamp,
		CancellationToken cancellationToken) =>
		context.Database.ExecuteSqlAsync(
			$"UPDATE public.user_credentials SET security_stamp = {stamp} WHERE id = {userId}", cancellationToken);
}
