using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     <see cref="TemporalIdentityVersioningSuite" /> over SQL Server 2025: native system versioning, history in
///     <c>[dbo].[UsersHistory]</c> (the principal-table-only seam) and EF's own <c>[dbo].[UserRolesHistory]</c>,
///     the period the HIDDEN <c>SystemPeriodStart</c>/<c>SystemPeriodEnd</c> pair, selected by name.
/// </summary>
/// <remarks>
///     The Postgres period-shape checks translate rather than drop. A SQL Server period is two
///     <c>datetime2</c> columns, not a range, so there is no <c>isempty</c>: "non-empty, positive length" is
///     <c>SystemPeriodEnd &gt; SystemPeriodStart</c>, which also rules out the zero-length versions SQL Server
///     writes when one transaction updates a row twice. "Closed" is an end below the open sentinel,
///     <c>9999-12-31 23:59:59.9999999</c>, in place of <c>'infinity'</c>. Adjacency is
///     <c>history.SystemPeriodEnd = current.SystemPeriodStart</c>.
/// </remarks>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerTemporalIdentityVersioningTests(SqlServerIdentityFixture fixture)
	: TemporalIdentityVersioningSuite(fixture)
{
	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;

	protected override Task<long> UserVersionsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
				$"SELECT COUNT_BIG(*) AS Value FROM [dbo].[UsersHistory] WHERE [Id] = {userId}")
			.SingleAsync(Cancellation);

	protected override Task<long> UserRoleVersionsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
				$"SELECT COUNT_BIG(*) AS Value FROM [dbo].[UserRolesHistory] WHERE [UserId] = {userId}")
			.SingleAsync(Cancellation);

	protected override Task<long> ClosedPositiveLengthUserVersionsAsync(NorseIdentityDbContext context,
		Guid userId) =>
		context.Database.SqlQuery<long>(
			$"""
			SELECT COUNT_BIG(*) AS Value FROM [dbo].[UsersHistory]
			WHERE [Id] = {userId}
				AND [SystemPeriodEnd] < '9999-12-31'
				AND [SystemPeriodEnd] > [SystemPeriodStart]
			""").SingleAsync(Cancellation);

	protected override Task<long> ClosedPositiveLengthUserRoleVersionsAsync(NorseIdentityDbContext context,
		Guid userId) =>
		context.Database.SqlQuery<long>(
			$"""
			SELECT COUNT_BIG(*) AS Value FROM [dbo].[UserRolesHistory]
			WHERE [UserId] = {userId}
				AND [SystemPeriodEnd] < '9999-12-31'
				AND [SystemPeriodEnd] > [SystemPeriodStart]
			""").SingleAsync(Cancellation);

	protected override Task<long> UserVersionsAdjacentToCurrentAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
			$"""
			SELECT COUNT_BIG(*) AS Value
			FROM [dbo].[UsersHistory] h JOIN [dbo].[Users] u ON u.[Id] = h.[Id]
			WHERE h.[Id] = {userId} AND h.[SystemPeriodEnd] = u.[SystemPeriodStart]
			""").SingleAsync(Cancellation);
}
