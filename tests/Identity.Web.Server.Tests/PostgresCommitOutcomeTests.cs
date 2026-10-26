
namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     <see cref="CommitOutcomeSuite" /> over <c>postgres:19rc1</c>, plus the PostgreSQL-only commit boundary: a failed
///     commit on a path without a stamp marker is resolved by <c>pg_xact_status</c>, never by a rollback probe, because a
///     <c>ROLLBACK</c> with no transaction in progress is only a warning there.
/// </summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresCommitOutcomeTests(PostgresIdentityFixture fixture) : CommitOutcomeSuite(fixture)
{
	/// <summary>
	///     The hole the rollback probe left: the commit landed, the connection survived, and the failure surfaced anyway.
	///     The probe's rollback is accepted with a warning, which would have called a landed commit definite (the
	///     instance restored, the caller free to repeat a write that already took effect); the transaction's status says
	///     committed, so the flush succeeds.
	/// </summary>
	[Fact]
	public async Task Commit_that_landed_on_a_surviving_connection_resolves_committed_not_definite()
	{
		fixture.SkipUnlessAvailable();
		var seeded = await fixture.SeedUserAsync("surviving-connection@example.com");
		CommitFailureInterceptor interceptor = new(CommitFailure.CommittedOnSurvivingConnection);
		var (manager, store) = InterceptedManager(interceptor);
		var user = (await manager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		await AddClaim(store, user);

		var result = await manager.UpdateAsync(user);

		interceptor.Fired.ShouldBe(1);
		interceptor.Commits.ShouldBe(1, "resolved by asking, never by replaying");
		interceptor.RollbacksAccepted.ShouldBe(1, "the server took the ROLLBACK with only a warning");
		result.Succeeded.ShouldBeTrue("pg_xact_status reports the transaction committed");
		(await ClaimsAsync(seeded.Id)).ShouldBe(["scope=alpha"]);
		NorseUserStore.TryGetBaseline(user, out _).ShouldBeTrue("a resolved commit is not poisoned");
	}

	/// <summary>
	///     The increment's acknowledgement lost while the database can still be asked: <c>pg_xact_status</c> says
	///     committed, so the increment returns as committed, counted exactly once and never repeated.
	/// </summary>
	[Fact]
	public async Task Increment_ack_loss_with_a_visible_status_resolves_committed_exactly_once()
	{
		fixture.SkipUnlessAvailable();
		var seeded = await SeedWithPasswordAsync("increment-status-visible@example.com");
		CommitFailureInterceptor interceptor = new(CommitFailure.AfterCommitOutcomeVisible);
		var (manager, _) = InterceptedManager(interceptor);
		var user = (await manager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		var result = await fixture.CreateSignInManager(manager)
			.CheckPasswordSignInAsync(user, "wrong-password", lockoutOnFailure: true);

		result.Succeeded.ShouldBeFalse("the password was wrong");
		interceptor.Fired.ShouldBe(1);
		interceptor.Commits.ShouldBe(1, "the increment is never repeated");
		(await RereadAsync(seeded.Id)).AccessFailedCount.ShouldBe(1, "the attempt counted exactly once");
		user.AccessFailedCount.ShouldBe(1);
		NorseUserStore.TryGetBaseline(user, out _).ShouldBeTrue("a resolved commit is not poisoned");
	}
}
