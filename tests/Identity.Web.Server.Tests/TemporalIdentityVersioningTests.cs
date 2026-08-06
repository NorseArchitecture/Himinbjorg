using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
/// What the temporal apparatus actually does once identity traffic starts moving: real
/// <c>UserManager</c>/<c>RoleManager</c>/<c>SignInManager</c> flows over a real, fully migrated
/// <c>postgres:19beta2</c> database. The migration suite proves the apparatus stands; this one proves
/// the platform's own write paths version through it.
/// </summary>
/// <remarks>
/// Every history reading here goes through raw SQL on purpose: <c>system_period</c> is database-owned
/// and outside the EF model (spec §3.2), and the history table is mapped by nothing at all. The period
/// predicates live in SQL rather than being materialized and re-checked in C# because
/// <c>Database.SqlQuery&lt;T&gt;</c> projects scalars only. Every count is scoped to the row the test
/// created, so the shared fixture's other traffic cannot color it.
/// </remarks>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class TemporalIdentityVersioningTests(PostgresIdentityFixture fixture)
{
	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task An_email_change_through_the_user_manager_writes_a_closed_version_into_users_history()
	{
		var user = await fixture.SeedUserAsync("temporal-before@example.com");
		var (context, _) = await fixture.CreateScopeAsync();
		// Standing first, so the assertions below cannot pass on some earlier row's history: an insert
		// opens a version, it does not close one.
		(await UserVersionsAsync(context, user.Id)).ShouldBe(0);
		var userManager = fixture.CreateUserManager();
		var reloaded = (await userManager.FindByIdAsync(user.Id.ToString()))!;

		(await userManager.SetEmailAsync(reloaded, "temporal-after@example.com")).Succeeded.ShouldBeTrue();

		(await UserVersionsAsync(context, user.Id)).ShouldBe(1);
		(await ClosedPositiveLengthUserVersionsAsync(context, user.Id)).ShouldBe(1,
			"the clamp guarantees every closed period is strictly positive, never empty");
		// The closed upper bound is the current version's lower bound: gapless by arithmetic, not by luck.
		(await UserVersionsAdjacentToCurrentAsync(context, user.Id)).ShouldBe(1);
	}

	[Fact]
	async Task A_role_grant_and_revoke_versions_user_roles()
	{
		var user = await fixture.SeedUserAsync("temporal-role-holder@example.com");
		var roleManager = fixture.CreateRoleManager();
		NorseRole role = new() { Name = "temporal-auditor" };
		(await roleManager.CreateAsync(role)).Succeeded.ShouldBeTrue();
		var userManager = fixture.CreateUserManager();
		var reloaded = (await userManager.FindByIdAsync(user.Id.ToString()))!;
		var (context, _) = await fixture.CreateScopeAsync();

		(await userManager.AddToRoleAsync(reloaded, role.Name)).Succeeded.ShouldBeTrue();
		// The grant only opens a version -- history stays empty until something supersedes it.
		(await UserRoleVersionsAsync(context, user.Id)).ShouldBe(0);
		(await userManager.RemoveFromRoleAsync(reloaded, role.Name)).Succeeded.ShouldBeTrue();

		(await context.Set<NorseUserRole>().CountAsync(ur => ur.UserId == user.Id, Cancellation)).ShouldBe(0,
			"the revoke really deletes the join row");
		(await UserRoleVersionsAsync(context, user.Id)).ShouldBe(1,
			"the revoke writes the grant's final closed version -- a role once held stays readable");
		(await ClosedPositiveLengthUserRoleVersionsAsync(context, user.Id)).ShouldBe(1);
	}

	[Fact]
	async Task A_failed_password_attempt_currently_versions_users()
	{
		// PINNED DELIBERATELY, AND EXPECTED TO FLIP. Lockout churn (AccessFailedCount/LockoutEnd) rides
		// the users row today, so a wrong password mints a history row -- accepted on the record for the
		// local proving ground (task-10 brief, gate partially waived 2026-08-05). The
		// feature/access-count-breakout split (Himinbjörg#47) moves those columns to their own
		// non-temporal user_lockout table at .NET 11 preview 7; the split task flips this assertion to
		// that issue's exit criterion -- "wrong-password churn never mints a history row" -- rather than
		// deleting it.
		var userManager = fixture.CreateUserManager();
		NorseUser user = new() { UserName = "temporal-lockout@example.com", Email = "temporal-lockout@example.com" };
		(await userManager.CreateAsync(user, "Correct-Horse-1!")).Succeeded.ShouldBeTrue();
		var (context, _) = await fixture.CreateScopeAsync();
		(await UserVersionsAsync(context, user.Id)).ShouldBe(0);
		var signInManager = fixture.CreateSignInManager();
		var reloaded = (await userManager.FindByIdAsync(user.Id.ToString()))!;

		var result = await signInManager.CheckPasswordSignInAsync(reloaded, "wrong-password", lockoutOnFailure: true);

		result.Succeeded.ShouldBeFalse();
		(await userManager.GetAccessFailedCountAsync(reloaded)).ShouldBe(1);
		(await UserVersionsAsync(context, user.Id)).ShouldBe(1);
	}

	static Task<long> UserVersionsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
			$"""SELECT count(*) AS "Value" FROM public.users_history WHERE id = {userId}""")
			.SingleAsync(Cancellation);

	static Task<long> UserRoleVersionsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
			$"""SELECT count(*) AS "Value" FROM public.user_roles_history WHERE user_id = {userId}""")
			.SingleAsync(Cancellation);

	// Empty ranges overlap nothing, so a WITHOUT OVERLAPS key admits any number of them -- isempty is
	// checked explicitly rather than trusting the key alone. The apparatus opens a period at
	// tstzrange(clock_timestamp(), 'infinity'), an upper bound that exists and holds the infinity
	// timestamp, so a closed version is one whose upper bound is not that value.
	static Task<long> ClosedPositiveLengthUserVersionsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
			$"""
			SELECT count(*) AS "Value" FROM public.users_history
			WHERE id = {userId}
				AND NOT isempty(system_period)
				AND upper(system_period) <> 'infinity'::timestamptz
				AND upper(system_period) > lower(system_period)
			""").SingleAsync(Cancellation);

	static Task<long> ClosedPositiveLengthUserRoleVersionsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
			$"""
			SELECT count(*) AS "Value" FROM public.user_roles_history
			WHERE user_id = {userId}
				AND NOT isempty(system_period)
				AND upper(system_period) <> 'infinity'::timestamptz
				AND upper(system_period) > lower(system_period)
			""").SingleAsync(Cancellation);

	static Task<long> UserVersionsAdjacentToCurrentAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Database.SqlQuery<long>(
			$"""
			SELECT count(*) AS "Value"
			FROM public.users_history h JOIN public.users u ON u.id = h.id
			WHERE h.id = {userId} AND upper(h.system_period) = lower(u.system_period)
			""").SingleAsync(Cancellation);
}
