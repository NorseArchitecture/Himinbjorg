using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     <see cref="TemporalIdentityVersioningSuite" /> over <c>postgres:19rc1</c>: history in
///     <c>public.*_history</c>, the period a <c>tstzrange</c> named <c>system_period</c>.
/// </summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresTemporalIdentityVersioningTests(PostgresIdentityFixture fixture)
	: TemporalIdentityVersioningSuite(fixture)
{
	protected override Task<long> UserVersionsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
				$"""SELECT count(*) AS "Value" FROM public.users_history WHERE id = {userId}""")
			.SingleAsync(Cancellation);

	protected override Task<long> UserRoleVersionsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
				$"""SELECT count(*) AS "Value" FROM public.user_roles_history WHERE user_id = {userId}""")
			.SingleAsync(Cancellation);

	// Empty ranges overlap nothing, so a WITHOUT OVERLAPS key admits any number of them -- isempty is
	// checked explicitly rather than trusting the key alone. The apparatus opens a period at
	// tstzrange(clock_timestamp(), 'infinity'), an upper bound that exists and holds the infinity
	// timestamp, so a closed version is one whose upper bound is not that value.
	protected override Task<long> ClosedPositiveLengthUserVersionsAsync(NorseIdentityDbContext context,
		Guid userId) =>
		context.Database.SqlQuery<long>(
			$"""
			SELECT count(*) AS "Value" FROM public.users_history
			WHERE id = {userId}
				AND NOT isempty(system_period)
				AND upper(system_period) <> 'infinity'::timestamptz
				AND upper(system_period) > lower(system_period)
			""").SingleAsync(Cancellation);

	protected override Task<long> ClosedPositiveLengthUserRoleVersionsAsync(NorseIdentityDbContext context,
		Guid userId) =>
		context.Database.SqlQuery<long>(
			$"""
			SELECT count(*) AS "Value" FROM public.user_roles_history
			WHERE user_id = {userId}
				AND NOT isempty(system_period)
				AND upper(system_period) <> 'infinity'::timestamptz
				AND upper(system_period) > lower(system_period)
			""").SingleAsync(Cancellation);

	protected override Task<long> UserVersionsAdjacentToCurrentAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
			$"""
			SELECT count(*) AS "Value"
			FROM public.users_history h JOIN public.users u ON u.id = h.id
			WHERE h.id = {userId} AND upper(h.system_period) = lower(u.system_period)
			""").SingleAsync(Cancellation);
}
