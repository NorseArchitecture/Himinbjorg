using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The last sign-in method guard (2026-10-26 account-lifecycle spec §5.9), once per provider: a user always keeps
///     a password or at least one external login. The store refuses the removal under the credentials row lock, so
///     the invariant holds for sequential removals on fresh instances and for concurrent ones alike.
/// </summary>
/// <remarks>
///     Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///     records: xUnit discovers them on each <see langword="sealed" /> provider class.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class LastSignInMethodSuite(IdentityFixture fixture)
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	/// <summary>The password every user with one starts with.</summary>
	const string Password = "Correct-Horse-1!";

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_passwordless_account_cannot_remove_its_only_login()
	{
		fixture.SkipUnlessAvailable();
		var userId = await SeedAsync(withPassword: false);
		await LinkAsync(userId, "A");
		var (userManager, user) = await FreshAsync(userId);

		var result = await userManager.RemoveLoginAsync(user, "A", KeyOf(userId, "A"));

		result.Succeeded.ShouldBeFalse();
		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(NorseIdentityErrorCodes.LastSignInMethod);
		(await userManager.GetLoginsAsync(user)).Count.ShouldBe(1);
		(await OrphansAsync(userId)).ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_second_sequential_removal_on_a_fresh_instance_is_refused()
	{
		fixture.SkipUnlessAvailable();
		var userId = await SeedAsync(withPassword: false);
		await LinkAsync(userId, "A");
		await LinkAsync(userId, "B");
		var (first, firstUser) = await FreshAsync(userId);
		(await first.RemoveLoginAsync(firstUser, "A", KeyOf(userId, "A"))).Succeeded.ShouldBeTrue();
		var (second, secondUser) = await FreshAsync(userId);

		var result = await second.RemoveLoginAsync(secondUser, "B", KeyOf(userId, "B"));

		result.Succeeded.ShouldBeFalse();
		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(NorseIdentityErrorCodes.LastSignInMethod);
		(await second.GetLoginsAsync(secondUser)).ShouldHaveSingleItem().LoginProvider.ShouldBe("B");
		(await OrphansAsync(userId)).ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Removing_a_login_the_account_does_not_have_is_a_no_op()
	{
		fixture.SkipUnlessAvailable();
		var userId = await SeedAsync(withPassword: false);
		await LinkAsync(userId, "A");
		var (userManager, user) = await FreshAsync(userId);

		(await userManager.RemoveLoginAsync(user, "Z", KeyOf(userId, "Z"))).Succeeded.ShouldBeTrue();

		(await userManager.GetLoginsAsync(user)).ShouldHaveSingleItem().LoginProvider.ShouldBe("A");
	}

	/// <summary>
	///     The manager rotates the stamp on every removal, so its CAS already holds the credentials row; a store flush
	///     with no stamp change has only the guard's own lock. A side transaction holds that lock and removes "A"
	///     while the flush removing "B" waits on it, so the flush must count after "A" is gone.
	/// </summary>
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_stampless_store_flush_counts_under_the_credentials_lock()
	{
		fixture.SkipUnlessAvailable();
		var userId = await SeedAsync(withPassword: false);
		await LinkAsync(userId, "A");
		await LinkAsync(userId, "B");
		var store = fixture.CreateUserStore();
		var user = (await store.FindByIdAsync(userId.ToString(), Cancellation)).ShouldNotBeNull();
		await ((IUserLoginStore<NorseUser>)store).RemoveLoginAsync(user, "B", KeyOf(userId, "B"), Cancellation);
		var (side, _) = await fixture.CreateScopeAsync();
		var key = KeyOf(userId, "A");
		Task<IdentityResult>? flush = null;

		// The registered retrying strategy refuses a bare user transaction; run the side transaction as its unit.
		await side.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
		{
			await using var transaction = await side.Database.BeginTransactionAsync(Cancellation);
			await LockCredentialsAsync(side, userId);
			flush = store.UpdateAsync(user, Cancellation);
			// Too short a delay can only let a lock-less build pass by mistake; it can never fail a correct one.
			await Task.Delay(TimeSpan.FromMilliseconds(500), Cancellation);
			await side.UserLogins
				.Where(l => l.UserId == userId && l.LoginProvider == "A" && l.ProviderKey == key)
				.ExecuteDeleteAsync(Cancellation);
			await transaction.CommitAsync(Cancellation);
		});
		var result = await flush.ShouldNotBeNull();

		result.Succeeded.ShouldBeFalse();
		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(NorseIdentityErrorCodes.LastSignInMethod);
		var (reading, reread) = await FreshAsync(userId);
		(await reading.GetLoginsAsync(reread)).ShouldHaveSingleItem().LoginProvider.ShouldBe("B");
		(await OrphansAsync(userId)).ShouldBe(0);
	}

	/// <summary>
	///     Takes the guard's lock on the user's credentials row inside <paramref name="context" />'s open transaction,
	///     in the provider's own spelling (<c>FOR UPDATE</c> / <c>WITH (UPDLOCK, HOLDLOCK)</c>).
	/// </summary>
	/// <param name="context">The side context, inside its transaction.</param>
	/// <param name="userId">The user.</param>
	protected abstract Task LockCredentialsAsync(NorseIdentityDbContext context, Guid userId);

	/// <summary>The current test's cancellation token.</summary>
	protected static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_password_account_can_remove_its_only_login()
	{
		fixture.SkipUnlessAvailable();
		var userId = await SeedAsync(withPassword: true);
		await LinkAsync(userId, "A");
		var (userManager, user) = await FreshAsync(userId);

		(await userManager.RemoveLoginAsync(user, "A", KeyOf(userId, "A"))).Succeeded.ShouldBeTrue();

		(await userManager.GetLoginsAsync(user)).ShouldBeEmpty();
		(await OrphansAsync(userId)).ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Two_concurrent_removals_from_a_passwordless_account_leave_exactly_one()
	{
		fixture.SkipUnlessAvailable();
		var userId = await SeedAsync(withPassword: false);
		await LinkAsync(userId, "A");
		await LinkAsync(userId, "B");
		var (removingA, userA) = await FreshAsync(userId);
		var (removingB, userB) = await FreshAsync(userId);

		var results = await Task.WhenAll(
			removingA.RemoveLoginAsync(userA, "A", KeyOf(userId, "A")),
			removingB.RemoveLoginAsync(userB, "B", KeyOf(userId, "B")));

		results.Count(static r => r.Succeeded).ShouldBe(1);
		results.Single(static r => !r.Succeeded).Errors.ShouldHaveSingleItem().Code
			.ShouldBeOneOf(NorseIdentityErrorCodes.LastSignInMethod, nameof(IdentityErrorDescriber.ConcurrencyFailure));
		var (reading, reread) = await FreshAsync(userId);
		(await reading.GetLoginsAsync(reread)).Count.ShouldBe(1);
		(await OrphansAsync(userId)).ShouldBe(0);
	}

	/// <summary>A new user, created through the real manager, with or without <see cref="Password" />.</summary>
	async Task<Guid> SeedAsync(bool withPassword)
	{
		var email = $"last-sign-in-{Guid.NewGuid():N}@example.com";
		NorseUser user = new() { UserName = email, Email = email };
		var userManager = fixture.CreateUserManager();
		(await (withPassword ?
			userManager.CreateAsync(user, Password) :
			userManager.CreateAsync(user))).Succeeded.ShouldBeTrue();
		return user.Id;
	}

	/// <summary>Links an external login from <paramref name="provider" />, on a fresh instance of its own.</summary>
	async Task LinkAsync(Guid userId, string provider)
	{
		var (userManager, user) = await FreshAsync(userId);
		(await userManager.AddLoginAsync(user, new(provider, KeyOf(userId, provider), provider))).Succeeded.ShouldBeTrue();
	}

	/// <summary>
	///     A new request's manager and the instance a <c>/Account/Manage</c> page works on: <c>GetUserAsync</c> on the
	///     signed-in principal.
	/// </summary>
	async Task<(UserManager<NorseUser> UserManager, NorseUser User)> FreshAsync(Guid userId)
	{
		var userManager = fixture.CreateUserManager();
		ClaimsPrincipal principal = new(new ClaimsIdentity(
			[new(userManager.Options.ClaimsIdentity.UserIdClaimType, userId.ToString())], "Test"));
		return (userManager, (await userManager.GetUserAsync(principal)).ShouldNotBeNull());
	}

	/// <summary>
	///     The invariant, on a fresh context: whether the user is left with neither a password nor an external login.
	///     Scoped to the test's own user, since the fixture is shared and other suites seed passwordless users that
	///     never link one.
	/// </summary>
	async Task<int> OrphansAsync(Guid userId)
	{
		var (context, _) = await fixture.CreateScopeAsync();
		return await context.Users.CountAsync(
			u => u.Id == userId && u.PasswordHash == null && !context.UserLogins.Any(l => l.UserId == u.Id),
			Cancellation);
	}

	static string KeyOf(Guid userId, string provider) =>
		$"{provider}-{userId:N}";
}
