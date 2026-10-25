using NpgsqlTypes;

namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="ErasureServiceSuite" /> over <c>postgres:19rc1</c>.</summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresErasureServiceTests(PostgresIdentityFixture fixture) : ErasureServiceSuite(fixture)
{
	protected override string UsersHistoryTable => "users_history";

	// The apparatus's system_period is one tstzrange.
	protected override Type PeriodType => typeof(NpgsqlRange<DateTime>);
}
