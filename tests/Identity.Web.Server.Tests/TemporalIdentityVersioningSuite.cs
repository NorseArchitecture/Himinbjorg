using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     What the temporal apparatus actually does once identity traffic starts moving: real
///     <c>UserManager</c>/<c>RoleManager</c>/<c>SignInManager</c> flows over a real, fully migrated database,
///     once per provider. The migration suites prove the apparatus stands; this one proves the platform's own
///     write paths version through it -- Postgres through Urðarbrunnr's trigger apparatus, SQL Server through
///     native system versioning.
/// </summary>
/// <remarks>
///     <para>
///         Every history reading goes through the provider's own raw SQL, behind the abstract seam below, on
///         purpose: the period columns are database-owned and outside the EF model (spec §3.2), and the history
///         tables are mapped by nothing at all. The period predicates live in SQL rather than being
///         materialized and re-checked in C# because <c>Database.SqlQuery&lt;T&gt;</c> projects scalars only.
///         Every count is scoped to the row the test created, so the shared fixture's other traffic cannot
///         color it.
///     </para>
///     <para>
///         Test methods are <see langword="protected" />, the one deviation from the bare-modifier test law:
///         xUnit discovers them on each <see langword="sealed" /> provider class, and reflection over a derived
///         type never sees a base type's private members. The <c>SkipUnless</c> gate is a static property the
///         base declares (xUnit1054 demands it on the declaring type) and a provider class hides when its container
///         is host-dependent; xUnit resolves it on the test class at run time.
///     </para>
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class TemporalIdentityVersioningSuite(IdentityFixture fixture)
{
	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	/// <summary>The current test's cancellation token.</summary>
	protected static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_email_change_through_the_user_manager_writes_a_closed_version_into_users_history()
	{
		fixture.SkipUnlessAvailable();
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
			"every closed period is strictly positive, never empty");
		// The closed upper bound is the current version's lower bound: gapless by arithmetic, not by luck.
		(await UserVersionsAdjacentToCurrentAsync(context, user.Id)).ShouldBe(1);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_role_grant_and_revoke_versions_user_roles()
	{
		fixture.SkipUnlessAvailable();
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

	/// <summary>How many superseded versions of one user row the history holds.</summary>
	protected abstract Task<long> UserVersionsAsync(NorseIdentityDbContext context, Guid userId);

	/// <summary>How many superseded versions of one user's role grants the history holds.</summary>
	protected abstract Task<long> UserRoleVersionsAsync(NorseIdentityDbContext context, Guid userId);

	/// <summary>How many of one user's history versions are closed, with a strictly positive length.</summary>
	protected abstract Task<long> ClosedPositiveLengthUserVersionsAsync(NorseIdentityDbContext context, Guid userId);

	/// <summary>How many of one user's role-grant history versions are closed, with a strictly positive length.</summary>
	protected abstract Task<long> ClosedPositiveLengthUserRoleVersionsAsync(NorseIdentityDbContext context,
		Guid userId);

	/// <summary>How many of one user's history versions end exactly where the current version starts.</summary>
	protected abstract Task<long> UserVersionsAdjacentToCurrentAsync(NorseIdentityDbContext context, Guid userId);
}
