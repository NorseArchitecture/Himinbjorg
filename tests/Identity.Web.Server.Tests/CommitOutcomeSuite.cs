using System.Buffers.Binary;
using System.Buffers.Text;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Backend.Keys;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Store;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The commit-outcome contract (2026-10-24 explicit-writes spec §4.10, plan Task 4.9), once per provider: for every
///     statement class of the §4.10 policy table, a failure before the commit is definite and leaves the database
///     unchanged; a lost acknowledgement resolves to committed where the flush carries the <c>users</c> stamp marker,
///     and otherwise answers <see cref="NorseUserStore.IndeterminateOutcomeErrorCode" /> and poisons the instance;
///     and the documented caller retry (re-read, then repeat) leaves exactly the intended state. The immediate
///     operations throw <see cref="IndeterminateWriteException" /> and are never repeated. Erasure's row is in
///     <see cref="ErasureServiceSuite" />.
/// </summary>
/// <remarks>
///     <para>
///         Every injection goes through <see cref="CommitFailureInterceptor" /> on a context of the test's own, under a
///         real <see cref="NorseUserManager" /> over a <see cref="NorseUserStore" />, and every test asserts the
///         interceptor fired. Each child-row class is staged on the store and flushed by
///         <see cref="UserManager{TUser}.UpdateAsync" />, so the flush holds exactly that class's statement (plus a
///         <c>users</c> column when the marker is the point); the caller's retry repeats the same statement on a
///         re-read instance.
///     </para>
///     <para>
///         Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///         records: xUnit discovers them on each <see langword="sealed" /> provider class.
///     </para>
/// </remarks>
public abstract class CommitOutcomeSuite : IDisposable
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	/// <summary>The password every <see cref="SeedWithPasswordAsync" /> user starts with.</summary>
	const string Password = "Correct-Horse-1!";

	/// <summary>The <c>users</c> column a marker test changes alongside its class, so the flush carries the stamp.</summary>
	const string MarkerPhone = "+15550999";

	/// <summary>Where stock Identity keeps the recovery-code set: its internal login provider and token name.</summary>
	const string RecoveryCodeProvider = "[AspNetUserStore]";

	const string RecoveryCodeName = "RecoveryCodes";

	/// <summary>The relying party every passkey assertion here is made for.</summary>
	const string RelyingParty = "localhost";

	static readonly DateTimeOffset _lockoutEnd = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);

	readonly IdentityFixture _fixture;
	readonly List<NorseIdentityDbContext> _contexts = [];

	/// <summary>Binds the suite to the provider's shared fixture.</summary>
	/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
	protected CommitOutcomeSuite(IdentityFixture fixture) =>
		_fixture = fixture;

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	/// <inheritdoc />
	public void Dispose()
	{
		foreach (var context in _contexts)
			context.Dispose();
		GC.SuppressFinalize(this);
	}

	// users scalar update: resolved by the stamp, never repeated.

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Users_scalar_update_failure_before_commit_is_definite_and_database_unchanged()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("users-before-commit@example.com", "+15550900");

		await BeforeCommitIsDefiniteAsync(seeded.Id, ChangePhone);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Users_scalar_update_ack_loss_resolves_committed_when_a_stamp_marker_exists()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("users-marker@example.com", "+15550900");

		await AckLossResolvesCommittedAsync(seeded.Id, static (_, _) => Task.CompletedTask);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Users_scalar_update_ack_loss_with_a_concurrent_writer_returns_IndeterminateOutcome_and_poisons_the_instance()
	{
		// A users flush always carries the marker, so its only indeterminate case is a third stamp (spec §4.10): a
		// writer that committed between the lost acknowledgement and the verification.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("users-concurrent-writer@example.com", "+15550900");
		var writersStamp = Guid.NewGuid().ToString();
		CommitFailureInterceptor interceptor = new(CommitFailure.AfterCommit, async cancellationToken =>
		{
			await using var writer = _fixture.CreateContext();
			(await writer.Users
				.Where(u => u.Id == seeded.Id)
				.ExecuteUpdateAsync(setters => setters.SetProperty(static u => u.ConcurrencyStamp, writersStamp), cancellationToken))
				.ShouldBe(1, "the concurrent writer commits between the commit and the verification");
		});

		await AckLossIsIndeterminateAndPoisonsAsync(seeded.Id, ChangePhone, interceptor);

		var reread = await RereadAsync(seeded.Id);
		reread.PhoneNumber.ShouldBe(MarkerPhone, "the flush committed");
		reread.ConcurrencyStamp.ShouldBe(writersStamp);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Users_scalar_update_ack_loss_then_documented_caller_retry_leaves_exactly_the_intended_state()
	{
		// Resolved, not repeated: once the stamp proves the commit, the re-read already holds the new values, so a
		// caller repeating the change has an empty diff and issues nothing (the stamp would move otherwise).
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("users-retry@example.com", "+15550900");
		await AckLossResolvesCommittedAsync(seeded.Id, static (_, _) => Task.CompletedTask);
		var committed = await RereadAsync(seeded.Id);

		await RepeatAsync(seeded.Id, ChangePhone);

		var reread = await RereadAsync(seeded.Id);
		reread.PhoneNumber.ShouldBe(MarkerPhone);
		reread.ConcurrencyStamp.ShouldBe(committed.ConcurrencyStamp, "the repeat issued no users statement");
	}

	// credential compare-and-swap: safe.

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Credential_CAS_failure_before_commit_is_definite_and_database_unchanged()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithPasswordAsync("credential-before-commit@example.com");

		await BeforeCommitIsDefiniteAsync(seeded.Id, RotateCredentials);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Credential_CAS_ack_loss_resolves_committed_when_a_stamp_marker_exists()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithPasswordAsync("credential-marker@example.com");

		var user = await AckLossResolvesCommittedAsync(seeded.Id, RotateCredentials);

		var reread = await RereadAsync(seeded.Id);
		reread.SecurityStamp.ShouldBe(user.SecurityStamp);
		reread.PasswordHash.ShouldBe(user.PasswordHash);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Credential_CAS_ack_loss_without_marker_returns_IndeterminateOutcome_and_poisons_the_instance()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithPasswordAsync("credential-indeterminate@example.com");

		var user = await AckLossIsIndeterminateAndPoisonsAsync(seeded.Id, RotateCredentials);

		var reread = await RereadAsync(seeded.Id);
		reread.SecurityStamp.ShouldBe(user.SecurityStamp, "the swap committed");
		reread.ConcurrencyStamp.ShouldBe(seeded.ConcurrencyStamp, "no users statement, so no marker");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Credential_CAS_ack_loss_then_documented_caller_retry_leaves_exactly_the_intended_state()
	{
		// The re-read rebaselines to the committed swap; repeating the same target is an empty diff.
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithPasswordAsync("credential-retry@example.com");

		await AckLossThenCallerRetryAsync(seeded.Id, RotateCredentials);

		var reread = await RereadAsync(seeded.Id);
		reread.SecurityStamp.ShouldBe(RotatedStamp(seeded.Id));
		reread.PasswordHash.ShouldBe(RotatedHash(seeded.Id));
	}

	// LockoutEnd set, AccessFailedCount reset: safe.

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Lockout_and_reset_failure_before_commit_is_definite_and_database_unchanged()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithFailuresAsync("lockout-before-commit@example.com");

		await BeforeCommitIsDefiniteAsync(seeded.Id, LockOutAndReset);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Lockout_and_reset_ack_loss_resolves_committed_when_a_stamp_marker_exists()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithFailuresAsync("lockout-marker@example.com");

		await AckLossResolvesCommittedAsync(seeded.Id, LockOutAndReset);

		await ShouldBeLockedOutAndResetAsync(seeded.Id);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Lockout_and_reset_ack_loss_without_marker_returns_IndeterminateOutcome_and_poisons_the_instance()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithFailuresAsync("lockout-indeterminate@example.com");

		await AckLossIsIndeterminateAndPoisonsAsync(seeded.Id, LockOutAndReset);

		await ShouldBeLockedOutAndResetAsync(seeded.Id);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Lockout_and_reset_ack_loss_then_documented_caller_retry_leaves_exactly_the_intended_state()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithFailuresAsync("lockout-retry@example.com");

		await AckLossThenCallerRetryAsync(seeded.Id, LockOutAndReset);

		await ShouldBeLockedOutAndResetAsync(seeded.Id);
	}

	// token upsert: safe.

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Token_upsert_failure_before_commit_is_definite_and_database_unchanged()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("token-before-commit@example.com");

		await BeforeCommitIsDefiniteAsync(seeded.Id, UpsertToken);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Token_upsert_ack_loss_resolves_committed_when_a_stamp_marker_exists()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("token-marker@example.com");

		await AckLossResolvesCommittedAsync(seeded.Id, UpsertToken);

		(await TokenValuesAsync(seeded.Id, "TestProvider", "refresh")).ShouldBe(["alpha"]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Token_upsert_ack_loss_without_marker_returns_IndeterminateOutcome_and_poisons_the_instance()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("token-indeterminate@example.com");

		await AckLossIsIndeterminateAndPoisonsAsync(seeded.Id, UpsertToken);

		(await TokenValuesAsync(seeded.Id, "TestProvider", "refresh")).ShouldBe(["alpha"]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Token_upsert_ack_loss_then_documented_caller_retry_leaves_exactly_the_intended_state()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("token-retry@example.com");

		await AckLossThenCallerRetryAsync(seeded.Id, UpsertToken);

		(await TokenValuesAsync(seeded.Id, "TestProvider", "refresh")).ShouldBe(["alpha"], "one token, one value");
	}

	// add claim: safe.

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Add_claim_failure_before_commit_is_definite_and_database_unchanged()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("claim-before-commit@example.com");

		await BeforeCommitIsDefiniteAsync(seeded.Id, AddClaim);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Add_claim_ack_loss_resolves_committed_when_a_stamp_marker_exists()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("claim-marker@example.com");

		await AckLossResolvesCommittedAsync(seeded.Id, AddClaim);

		(await ClaimsAsync(seeded.Id)).ShouldBe(["scope=alpha"]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Add_claim_ack_loss_without_marker_returns_IndeterminateOutcome_and_poisons_the_instance()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("claim-indeterminate@example.com");

		await AckLossIsIndeterminateAndPoisonsAsync(seeded.Id, AddClaim);

		(await ClaimsAsync(seeded.Id)).ShouldBe(["scope=alpha"]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Add_claim_ack_loss_then_documented_caller_retry_leaves_exactly_the_intended_state()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("claim-retry@example.com");

		await AckLossThenCallerRetryAsync(seeded.Id, AddClaim);

		(await ClaimsAsync(seeded.Id)).ShouldBe(["scope=alpha"], "one claim");
	}

	// add role: safe.

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Add_role_failure_before_commit_is_definite_and_database_unchanged()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("role-before-commit@example.com");
		var role = await SeedRoleAsync();

		await BeforeCommitIsDefiniteAsync(seeded.Id, AddRole(role));
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Add_role_ack_loss_resolves_committed_when_a_stamp_marker_exists()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("role-marker@example.com");
		var role = await SeedRoleAsync();

		await AckLossResolvesCommittedAsync(seeded.Id, AddRole(role));

		(await RoleIdsAsync(seeded.Id)).ShouldBe([role.Id]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Add_role_ack_loss_without_marker_returns_IndeterminateOutcome_and_poisons_the_instance()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("role-indeterminate@example.com");
		var role = await SeedRoleAsync();

		await AckLossIsIndeterminateAndPoisonsAsync(seeded.Id, AddRole(role));

		(await RoleIdsAsync(seeded.Id)).ShouldBe([role.Id]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Add_role_ack_loss_then_documented_caller_retry_leaves_exactly_the_intended_state()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("role-retry@example.com");
		var role = await SeedRoleAsync();

		await AckLossThenCallerRetryAsync(seeded.Id, AddRole(role));

		(await RoleIdsAsync(seeded.Id)).ShouldBe([role.Id], "one membership");
	}

	// add login: safe.

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Add_login_failure_before_commit_is_definite_and_database_unchanged()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("login-before-commit@example.com");

		await BeforeCommitIsDefiniteAsync(seeded.Id, AddLogin(seeded.Id));
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Add_login_ack_loss_resolves_committed_when_a_stamp_marker_exists()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("login-marker@example.com");

		await AckLossResolvesCommittedAsync(seeded.Id, AddLogin(seeded.Id));

		(await LoginsAsync(seeded.Id)).ShouldBe([LoginKey(seeded.Id)]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Add_login_ack_loss_without_marker_returns_IndeterminateOutcome_and_poisons_the_instance()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("login-indeterminate@example.com");

		await AckLossIsIndeterminateAndPoisonsAsync(seeded.Id, AddLogin(seeded.Id));

		(await LoginsAsync(seeded.Id)).ShouldBe([LoginKey(seeded.Id)]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Add_login_ack_loss_then_documented_caller_retry_leaves_exactly_the_intended_state()
	{
		// The repeat's insert meets the committed row, which is the same user's: a replay, under the savepoint.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("login-retry@example.com");

		await AckLossThenCallerRetryAsync(seeded.Id, AddLogin(seeded.Id));

		(await LoginsAsync(seeded.Id)).ShouldBe([LoginKey(seeded.Id)], "one login");
	}

	// passkey enrollment: safe.

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Passkey_enrollment_failure_before_commit_is_definite_and_database_unchanged()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("enroll-before-commit@example.com");

		await BeforeCommitIsDefiniteAsync(seeded.Id, EnrollPasskey(seeded.Id));
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Passkey_enrollment_ack_loss_resolves_committed_when_a_stamp_marker_exists()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("enroll-marker@example.com");

		await AckLossResolvesCommittedAsync(seeded.Id, EnrollPasskey(seeded.Id));

		(await PasskeysAsync(seeded.Id)).ShouldBe([PasskeyRow(seeded.Id, 0)]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Passkey_enrollment_ack_loss_without_marker_returns_IndeterminateOutcome_and_poisons_the_instance()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("enroll-indeterminate@example.com");

		await AckLossIsIndeterminateAndPoisonsAsync(seeded.Id, EnrollPasskey(seeded.Id));

		(await PasskeysAsync(seeded.Id)).ShouldBe([PasskeyRow(seeded.Id, 0)]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Passkey_enrollment_ack_loss_then_documented_caller_retry_leaves_exactly_the_intended_state()
	{
		// The repeat's insert meets an identical row, same user and public key: a replay.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("enroll-retry@example.com");

		await AckLossThenCallerRetryAsync(seeded.Id, EnrollPasskey(seeded.Id));

		(await PasskeysAsync(seeded.Id)).ShouldBe([PasskeyRow(seeded.Id, 0)], "one passkey");
	}

	// replace claim: safe.

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Replace_claim_failure_before_commit_is_definite_and_database_unchanged()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("replace-before-commit@example.com");
		await SeedClaimAsync(seeded.Id, "department", "sales");

		await BeforeCommitIsDefiniteAsync(seeded.Id, ReplaceClaim);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Replace_claim_ack_loss_resolves_committed_when_a_stamp_marker_exists()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("replace-marker@example.com");
		await SeedClaimAsync(seeded.Id, "department", "sales");

		await AckLossResolvesCommittedAsync(seeded.Id, ReplaceClaim);

		(await ClaimsAsync(seeded.Id)).ShouldBe(["department=support"]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Replace_claim_ack_loss_without_marker_returns_IndeterminateOutcome_and_poisons_the_instance()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("replace-indeterminate@example.com");
		await SeedClaimAsync(seeded.Id, "department", "sales");

		await AckLossIsIndeterminateAndPoisonsAsync(seeded.Id, ReplaceClaim);

		(await ClaimsAsync(seeded.Id)).ShouldBe(["department=support"]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Replace_claim_ack_loss_then_documented_caller_retry_leaves_exactly_the_intended_state()
	{
		// "New present, old absent" is success: the repeat matches nothing and finds the new claim already held.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("replace-retry@example.com");
		await SeedClaimAsync(seeded.Id, "department", "sales");

		await AckLossThenCallerRetryAsync(seeded.Id, ReplaceClaim);

		(await ClaimsAsync(seeded.Id)).ShouldBe(["department=support"]);
	}

	// passkey assertion update: fails closed.

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Passkey_assertion_failure_before_commit_is_definite_and_database_unchanged()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("assertion-before-commit@example.com");
		await SeedPasskeyAsync(seeded.Id, CredentialId(seeded.Id), [1, 2, 3], signCount: 3);

		await BeforeCommitIsDefiniteAsync(seeded.Id, AssertPasskey(seeded.Id));
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Passkey_assertion_ack_loss_resolves_committed_when_a_stamp_marker_exists()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("assertion-marker@example.com");
		await SeedPasskeyAsync(seeded.Id, CredentialId(seeded.Id), [1, 2, 3], signCount: 3);

		await AckLossResolvesCommittedAsync(seeded.Id, AssertPasskey(seeded.Id));

		(await PasskeysAsync(seeded.Id)).ShouldBe([PasskeyRow(seeded.Id, 4)]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Passkey_assertion_ack_loss_without_marker_returns_IndeterminateOutcome_and_poisons_the_instance()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("assertion-indeterminate@example.com");
		await SeedPasskeyAsync(seeded.Id, CredentialId(seeded.Id), [1, 2, 3], signCount: 3);

		await AckLossIsIndeterminateAndPoisonsAsync(seeded.Id, AssertPasskey(seeded.Id));

		(await PasskeysAsync(seeded.Id)).ShouldBe([PasskeyRow(seeded.Id, 4)]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Passkey_assertion_ack_loss_retry_fails_closed()
	{
		// The class's caller retry, through the real PasskeyHandler: the same signed assertion, replayed after the
		// re-read, proposes a count that is no longer greater than the committed one, so sign-in fails. The user signs
		// in again.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("assertion-retry@example.com");
		using ECDsa authenticator = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		var credentialId = CredentialId(seeded.Id);
		await SeedPasskeyAsync(seeded.Id, credentialId, CosePublicKey(authenticator), signCount: 3);
		CommitFailureInterceptor interceptor = new(CommitFailure.AfterCommit);
		var (manager, _) = InterceptedManager(interceptor);
		var user = (await manager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var http = AssertionHttpContext();
		var options = await PasskeyHandler(manager).MakeRequestOptionsAsync(user, http);
		var credentialJson = SignAssertion(authenticator, credentialId, seeded.Id, Challenge(options.RequestOptionsJson), signCount: 4);
		PasskeyAssertionContext assertion = new() { HttpContext = http, CredentialJson = credentialJson, AssertionState = options.AssertionState };
		var first = await PasskeyHandler(manager).PerformAssertionAsync(assertion);
		first.Succeeded.ShouldBeTrue(first.Failure?.Message);
		var asserted = first.User.ShouldNotBeNull();

		// SignInManager.PasskeySignInAsync's own next step (V7): the assertion update.
		var result = await manager.AddOrUpdatePasskeyAsync(asserted, first.Passkey.ShouldNotBeNull());

		interceptor.Fired.ShouldBe(1);
		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(NorseUserStore.IndeterminateOutcomeErrorCode);
		(await PasskeysAsync(seeded.Id)).ShouldBe([PasskeyRow(seeded.Id, 4)], "the update committed");
		var (retryManager, _) = InterceptedManager(new(CommitFailure.None));

		var retry = await PasskeyHandler(retryManager).PerformAssertionAsync(assertion);

		retry.Succeeded.ShouldBeFalse("the replayed assertion's count is not greater than the committed one");
		(await PasskeysAsync(seeded.Id)).ShouldBe([PasskeyRow(seeded.Id, 4)]);
		interceptor.Commits.ShouldBe(1);
	}

	// any delete by key: safe.

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Delete_by_key_failure_before_commit_is_definite_and_database_unchanged()
	{
		_fixture.SkipUnlessAvailable();
		var (seeded, role) = await SeedChildRowsAsync("delete-before-commit@example.com");

		await BeforeCommitIsDefiniteAsync(seeded.Id, DeleteEveryChild(seeded.Id, role));
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Delete_by_key_ack_loss_resolves_committed_when_a_stamp_marker_exists()
	{
		_fixture.SkipUnlessAvailable();
		var (seeded, role) = await SeedChildRowsAsync("delete-marker@example.com");

		await AckLossResolvesCommittedAsync(seeded.Id, DeleteEveryChild(seeded.Id, role));

		await ShouldHaveNoChildRowsAsync(seeded.Id);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Delete_by_key_ack_loss_without_marker_returns_IndeterminateOutcome_and_poisons_the_instance()
	{
		_fixture.SkipUnlessAvailable();
		var (seeded, role) = await SeedChildRowsAsync("delete-indeterminate@example.com");

		await AckLossIsIndeterminateAndPoisonsAsync(seeded.Id, DeleteEveryChild(seeded.Id, role));

		await ShouldHaveNoChildRowsAsync(seeded.Id);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Delete_by_key_ack_loss_then_documented_caller_retry_leaves_exactly_the_intended_state()
	{
		_fixture.SkipUnlessAvailable();
		var (seeded, role) = await SeedChildRowsAsync("delete-retry@example.com");

		await AckLossThenCallerRetryAsync(seeded.Id, DeleteEveryChild(seeded.Id, role));

		await ShouldHaveNoChildRowsAsync(seeded.Id);
	}

	// IncrementAccessFailedCountAsync, RedeemCodeAsync: never repeated. No marker exists for either (spec §4.10).

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Increment_failure_before_commit_is_definite_and_database_unchanged()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithPasswordAsync("increment-before-commit@example.com");
		CommitFailureInterceptor interceptor = new(CommitFailure.BeforeCommit);
		var (manager, _) = InterceptedManager(interceptor);
		var user = (await manager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		NorseUserStore.TryGetBaseline(user, out var asRead).ShouldBeTrue();

		await Should.ThrowAsync<SimulatedDbException>(() =>
			_fixture.CreateSignInManager(manager).CheckPasswordSignInAsync(user, "wrong-password", lockoutOnFailure: true));

		interceptor.Fired.ShouldBe(1);
		interceptor.Commits.ShouldBe(1);
		(await RereadAsync(seeded.Id)).AccessFailedCount.ShouldBe(0, "the increment rolled back");
		user.AccessFailedCount.ShouldBe(0);
		NorseUserStore.TryGetBaseline(user, out var baseline).ShouldBeTrue("a definite failure never poisons");
		baseline.ShouldBeSameAs(asRead);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Increment_ack_loss_throws_IndeterminateWriteException_committed_exactly_once()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithPasswordAsync("increment-ack-loss@example.com");
		CommitFailureInterceptor interceptor = new(CommitFailure.AfterCommit);
		var (manager, _) = InterceptedManager(interceptor);
		var user = (await manager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		await Should.ThrowAsync<IndeterminateWriteException>(() =>
			_fixture.CreateSignInManager(manager).CheckPasswordSignInAsync(user, "wrong-password", lockoutOnFailure: true));

		interceptor.Fired.ShouldBe(1);
		interceptor.Commits.ShouldBe(1, "the increment is never repeated");
		(await RereadAsync(seeded.Id)).AccessFailedCount.ShouldBe(1, "the attempt counted exactly once");
		NorseUserStore.TryGetBaseline(user, out _).ShouldBeFalse("the instance is poisoned");
		await Should.ThrowAsync<InvalidOperationException>(() => manager.UpdateAsync(user));
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Redemption_failure_before_commit_is_definite_and_database_unchanged()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("redeem-before-commit@example.com");
		await SeedRecoveryCodesAsync(seeded.Id, "alpha;bravo;charlie");
		CommitFailureInterceptor interceptor = new(CommitFailure.BeforeCommit);
		var (manager, _) = InterceptedManager(interceptor);
		var user = (await manager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		NorseUserStore.TryGetBaseline(user, out var asRead).ShouldBeTrue();

		await Should.ThrowAsync<SimulatedDbException>(() => manager.RedeemTwoFactorRecoveryCodeAsync(user, "alpha"));

		interceptor.Fired.ShouldBe(1);
		interceptor.Commits.ShouldBe(1, "a failed attempt is not retried");
		(await TokenValuesAsync(seeded.Id, RecoveryCodeProvider, RecoveryCodeName)).ShouldBe(["alpha;bravo;charlie"]);
		NorseUserStore.TryGetBaseline(user, out var baseline).ShouldBeTrue("a definite failure never poisons");
		baseline.ShouldBeSameAs(asRead);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Redemption_ack_loss_throws_and_the_code_is_consumed_exactly_once()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("redeem-ack-loss@example.com");
		await SeedRecoveryCodesAsync(seeded.Id, "alpha;bravo;charlie");
		CommitFailureInterceptor interceptor = new(CommitFailure.AfterCommit);
		var (manager, _) = InterceptedManager(interceptor);
		var user = (await manager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		await Should.ThrowAsync<IndeterminateWriteException>(() => manager.RedeemTwoFactorRecoveryCodeAsync(user, "alpha"));

		interceptor.Fired.ShouldBe(1);
		interceptor.Commits.ShouldBe(1, "the redemption is never repeated");
		(await TokenValuesAsync(seeded.Id, RecoveryCodeProvider, RecoveryCodeName)).ShouldBe(["bravo;charlie"]);
		NorseUserStore.TryGetBaseline(user, out _).ShouldBeFalse("the instance is poisoned");
		var rereadManager = _fixture.CreateUserManager();
		var reread = (await rereadManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		(await rereadManager.RedeemTwoFactorRecoveryCodeAsync(reread, "alpha")).Errors.ShouldHaveSingleItem().Code
			.ShouldBe(nameof(IdentityErrorDescriber.RecoveryCodeRedemptionFailed), "the code was consumed, exactly once");
	}

	/// <summary>
	///     A failure before the commit: the original failure surfaces, nothing changed in the database, and the instance
	///     is restored to exactly as read, keeping its baseline (§4.8).
	/// </summary>
	async Task BeforeCommitIsDefiniteAsync(Guid userId, Func<NorseUserStore, NorseUser, Task> stage)
	{
		CommitFailureInterceptor interceptor = new(CommitFailure.BeforeCommit);
		var (manager, store) = InterceptedManager(interceptor);
		var user = (await manager.FindByIdAsync(userId.ToString())).ShouldNotBeNull();
		var asRead = UserBaseline.Capture(user);
		var before = await SnapshotAsync(userId);
		await stage(store, user);
		NorseUserStore.TryGetBaseline(user, out var staged).ShouldBeTrue();

		await Should.ThrowAsync<SimulatedDbException>(() => manager.UpdateAsync(user));

		interceptor.Fired.ShouldBe(1);
		interceptor.Commits.ShouldBe(1, "nothing replays the flush");
		(await SnapshotAsync(userId)).ShouldBe(before, "a failure before the commit leaves the database unchanged");
		UserBaseline.Capture(user).ShouldBe(asRead, "a definite failure leaves the instance exactly as read");
		NorseUserStore.TryGetBaseline(user, out var baseline).ShouldBeTrue("a definite failure never poisons");
		baseline.ShouldBeSameAs(staged, "a failure never refreshes the baseline");
	}

	/// <summary>
	///     The class's statement plus a <c>users</c> column, then the acknowledgement lost: the stamp, read on a fresh
	///     connection, proves the commit, so the flush succeeds and the baseline is refreshed to what committed.
	/// </summary>
	async Task<NorseUser> AckLossResolvesCommittedAsync(Guid userId, Func<NorseUserStore, NorseUser, Task> stage)
	{
		CommitFailureInterceptor interceptor = new(CommitFailure.AfterCommit);
		var (manager, store) = InterceptedManager(interceptor);
		var user = (await manager.FindByIdAsync(userId.ToString())).ShouldNotBeNull();
		var asReadStamp = user.ConcurrencyStamp;
		await stage(store, user);
		user.PhoneNumber = MarkerPhone;

		var result = await manager.UpdateAsync(user);

		interceptor.Fired.ShouldBe(1);
		interceptor.Commits.ShouldBe(1, "resolved by reading, never by replaying");
		result.Succeeded.ShouldBeTrue("the stamp read on a fresh connection proves the commit landed");
		user.ConcurrencyStamp.ShouldNotBe(asReadStamp);
		var reread = await RereadAsync(userId);
		reread.ConcurrencyStamp.ShouldBe(user.ConcurrencyStamp);
		reread.PhoneNumber.ShouldBe(MarkerPhone);
		NorseUserStore.TryGetBaseline(user, out var baseline).ShouldBeTrue("a resolved commit is not poisoned");
		baseline.ConcurrencyStamp.ShouldBe(user.ConcurrencyStamp, "the baseline is what committed");
		baseline.PhoneNumber.ShouldBe(MarkerPhone);
		return user;
	}

	/// <summary>
	///     The class's statement alone, then the acknowledgement lost: no marker, so <c>IndeterminateOutcome</c>, the
	///     instance poisoned against any further write, and nothing replayed.
	/// </summary>
	async Task<NorseUser> AckLossIsIndeterminateAndPoisonsAsync(Guid userId, Func<NorseUserStore, NorseUser, Task> stage,
		CommitFailureInterceptor? interceptor = null)
	{
		interceptor ??= new(CommitFailure.AfterCommit);
		var (manager, store) = InterceptedManager(interceptor);
		var user = (await manager.FindByIdAsync(userId.ToString())).ShouldNotBeNull();
		await stage(store, user);

		var result = await manager.UpdateAsync(user);

		interceptor.Fired.ShouldBe(1);
		result.Succeeded.ShouldBeFalse();
		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(NorseUserStore.IndeterminateOutcomeErrorCode);
		NorseUserStore.TryGetBaseline(user, out _).ShouldBeFalse("the instance is poisoned until the caller re-reads");
		await Should.ThrowAsync<InvalidOperationException>(() => manager.UpdateAsync(user));
		interceptor.Commits.ShouldBe(1, "nothing replays the flush");
		return user;
	}

	/// <summary>The indeterminate flush, then the documented recovery: re-read, then repeat the same statement.</summary>
	async Task AckLossThenCallerRetryAsync(Guid userId, Func<NorseUserStore, NorseUser, Task> stage)
	{
		await AckLossIsIndeterminateAndPoisonsAsync(userId, stage);

		await RepeatAsync(userId, stage);
	}

	/// <summary>The caller's repeat: a fresh read through a fresh store, the same statement, and success.</summary>
	async Task RepeatAsync(Guid userId, Func<NorseUserStore, NorseUser, Task> stage)
	{
		var (manager, store) = InterceptedManager(new(CommitFailure.None));
		var reread = (await manager.FindByIdAsync(userId.ToString())).ShouldNotBeNull();
		await stage(store, reread);

		var result = await manager.UpdateAsync(reread);

		result.Succeeded.ShouldBeTrue(string.Join(", ", result.Errors.Select(static error => error.Code)));
	}

	/// <summary>A real <see cref="NorseUserManager" /> over a <see cref="NorseUserStore" /> whose own context carries <paramref name="interceptor" />.</summary>
	private protected (NorseUserManager Manager, NorseUserStore Store) InterceptedManager(CommitFailureInterceptor interceptor)
	{
		var context = _fixture.CreateContext(interceptor);
		_contexts.Add(context);
		NorseUserStore store = new(context, new());
		return (_fixture.CreateUserManager(store), store);
	}

	static Task ChangePhone(NorseUserStore store, NorseUser user) =>
		store.SetPhoneNumberAsync(user, MarkerPhone, Cancellation);

	/// <summary>A password change's two credential columns, swapped together, to values the retry can name again.</summary>
	static async Task RotateCredentials(NorseUserStore store, NorseUser user)
	{
		await store.SetPasswordHashAsync(user, RotatedHash(user.Id), Cancellation);
		await store.SetSecurityStampAsync(user, RotatedStamp(user.Id), Cancellation);
	}

	/// <summary>A hash in the column's stored shape (base64), which the retry can name again.</summary>
	static string RotatedHash(Guid userId) =>
		Convert.ToBase64String(userId.ToByteArray());

	static string RotatedStamp(Guid userId) =>
		$"{userId:N}".ToUpperInvariant();

	static async Task LockOutAndReset(NorseUserStore store, NorseUser user)
	{
		await store.SetLockoutEndDateAsync(user, _lockoutEnd, Cancellation);
		await store.ResetAccessFailedCountAsync(user, Cancellation);
	}

	static Task UpsertToken(NorseUserStore store, NorseUser user) =>
		store.SetTokenAsync(user, "TestProvider", "refresh", "alpha", Cancellation);

	private protected static Task AddClaim(NorseUserStore store, NorseUser user) =>
		store.AddClaimsAsync(user, [new("scope", "alpha")], Cancellation);

	static Func<NorseUserStore, NorseUser, Task> AddRole(NorseRole role) =>
		(store, user) => store.AddToRoleAsync(user, role.NormalizedName.ShouldNotBeNull(), Cancellation);

	static Func<NorseUserStore, NorseUser, Task> AddLogin(Guid userId) =>
		(store, user) => store.AddLoginAsync(user, new("TestProvider", LoginKey(userId), "Test"), Cancellation);

	static string LoginKey(Guid userId) =>
		$"commit-outcome-{userId:N}";

	static Func<NorseUserStore, NorseUser, Task> EnrollPasskey(Guid userId) =>
		(store, user) => store.AddOrUpdatePasskeyAsync(user,
			new(CredentialId(userId), [7, 7, 7], DateTimeOffset.UtcNow, 0, ["internal"], true, false, false, [4], [5]), Cancellation);

	static Task ReplaceClaim(NorseUserStore store, NorseUser user) =>
		store.ReplaceClaimAsync(user, new("department", "sales"), new("department", "support"), Cancellation);

	/// <summary>An assertion update as <c>PasskeyHandler</c> drives it: read the passkey through the store, then count up.</summary>
	static Func<NorseUserStore, NorseUser, Task> AssertPasskey(Guid userId) =>
		async (store, user) =>
		{
			var passkey = (await store.FindPasskeyAsync(user, CredentialId(userId), Cancellation)).ShouldNotBeNull();
			passkey.SignCount++;
			await store.AddOrUpdatePasskeyAsync(user, passkey, Cancellation);
		};

	static Func<NorseUserStore, NorseUser, Task> DeleteEveryChild(Guid userId, NorseRole role) =>
		async (store, user) =>
		{
			await store.RemoveClaimsAsync(user, [new Claim("department", "sales")], Cancellation);
			await store.RemoveFromRoleAsync(user, role.NormalizedName.ShouldNotBeNull(), Cancellation);
			await store.RemoveLoginAsync(user, "TestProvider", LoginKey(userId), Cancellation);
			await store.RemoveTokenAsync(user, "TestProvider", "refresh", Cancellation);
			await store.RemovePasskeyAsync(user, CredentialId(userId), Cancellation);
		};

	static byte[] CredentialId(Guid userId) =>
		[.. userId.ToByteArray(), 9];

	static string PasskeyRow(Guid userId, uint signCount) =>
		$"{Convert.ToBase64String(CredentialId(userId))}#{signCount}";

	/// <summary>Everything one user's rows hold, as one comparable string.</summary>
	async Task<string> SnapshotAsync(Guid userId)
	{
		await using var verify = _fixture.CreateContext();
		var user = await verify.Users
			.AsNoTracking()
			.SingleAsync(u => u.Id == userId, Cancellation);
		List<string> rows =
		[
			$"users {user.ConcurrencyStamp} {user.PhoneNumber} {user.PasswordHash} {user.SecurityStamp} {user.LockoutEnd:O} {user.AccessFailedCount}",
			.. (await ClaimsAsync(userId)).Select(static claim => $"claim {claim}"),
			.. (await RoleIdsAsync(userId)).Select(static role => $"role {role}"),
			.. (await LoginsAsync(userId)).Select(static login => $"login {login}"),
			.. (await TokenValuesAsync(userId, "TestProvider", "refresh")).Select(static token => $"token {token}"),
			.. (await TokenValuesAsync(userId, RecoveryCodeProvider, RecoveryCodeName)).Select(static codes => $"codes {codes}"),
			.. (await PasskeysAsync(userId)).Select(static passkey => $"passkey {passkey}")
		];
		return string.Join('\n', rows);
	}

	private protected async Task<List<string>> ClaimsAsync(Guid userId)
	{
		await using var verify = _fixture.CreateContext();
		var claims = await verify.UserClaims
			.AsNoTracking()
			.Where(c => c.UserId == userId)
			.Select(static c => new { c.ClaimType, c.ClaimValue })
			.ToListAsync(Cancellation);
		return [.. claims.Select(static c => $"{c.ClaimType}={c.ClaimValue}").Order(StringComparer.Ordinal)];
	}

	async Task<List<Guid>> RoleIdsAsync(Guid userId)
	{
		await using var verify = _fixture.CreateContext();
		return await verify.UserRoles
			.AsNoTracking()
			.Where(r => r.UserId == userId)
			.Select(static r => r.RoleId)
			.ToListAsync(Cancellation);
	}

	async Task<List<string>> LoginsAsync(Guid userId)
	{
		await using var verify = _fixture.CreateContext();
		return await verify.UserLogins
			.AsNoTracking()
			.Where(l => l.UserId == userId)
			.Select(static l => l.ProviderKey)
			.ToListAsync(Cancellation);
	}

	async Task<List<string?>> TokenValuesAsync(Guid userId, string loginProvider, string name)
	{
		await using var verify = _fixture.CreateContext();
		return await verify.UserTokens
			.AsNoTracking()
			.Where(t => t.UserId == userId && t.LoginProvider == loginProvider && t.Name == name)
			.Select(static t => t.Value)
			.ToListAsync(Cancellation);
	}

	async Task<List<string>> PasskeysAsync(Guid userId)
	{
		await using var verify = _fixture.CreateContext();
		var passkeys = await verify.UserPasskeys
			.AsNoTracking()
			.Where(p => p.UserId == userId)
			.ToListAsync(Cancellation);
		return [.. passkeys.Select(static p => $"{Convert.ToBase64String(p.CredentialId)}#{p.Data.SignCount}")];
	}

	async Task ShouldBeLockedOutAndResetAsync(Guid userId)
	{
		var reread = await RereadAsync(userId);
		reread.LockoutEnd.ShouldBe(_lockoutEnd);
		reread.AccessFailedCount.ShouldBe(0);
	}

	async Task ShouldHaveNoChildRowsAsync(Guid userId)
	{
		(await ClaimsAsync(userId)).ShouldBeEmpty();
		(await RoleIdsAsync(userId)).ShouldBeEmpty();
		(await LoginsAsync(userId)).ShouldBeEmpty();
		(await TokenValuesAsync(userId, "TestProvider", "refresh")).ShouldBeEmpty();
		(await PasskeysAsync(userId)).ShouldBeEmpty();
	}

	private protected async Task<NorseUser> RereadAsync(Guid userId) =>
		(await _fixture.CreateUserStore().FindByIdAsync(userId.ToString(), Cancellation)).ShouldNotBeNull();

	private protected async Task<NorseUser> SeedWithPasswordAsync(string email)
	{
		NorseUser user = new() { UserName = email, Email = email };
		(await _fixture.CreateUserManager().CreateAsync(user, Password)).Succeeded.ShouldBeTrue();
		return user;
	}

	/// <summary>A user with two failed attempts on record, so the reset has a count to clear.</summary>
	async Task<NorseUser> SeedWithFailuresAsync(string email)
	{
		var seeded = await SeedWithPasswordAsync(email);
		var store = (IUserLockoutStore<NorseUser>)_fixture.CreateUserStore();
		var user = (await store.FindByIdAsync(seeded.Id.ToString(), Cancellation)).ShouldNotBeNull();
		await store.IncrementAccessFailedCountAsync(user, Cancellation);
		(await store.IncrementAccessFailedCountAsync(user, Cancellation)).ShouldBe(2);
		return seeded;
	}

	async Task<NorseRole> SeedRoleAsync()
	{
		NorseRole role = new() { Name = $"commit-outcome-{Guid.NewGuid():N}" };
		(await _fixture.CreateRoleManager().CreateAsync(role)).Succeeded.ShouldBeTrue();
		return role;
	}

	async Task SeedClaimAsync(Guid userId, string type, string value)
	{
		await using var seed = _fixture.CreateContext();
		seed.UserClaims.Add(new() { UserId = userId, ClaimType = type, ClaimValue = value });
		await seed.SaveChangesAsync(Cancellation);
	}

	async Task SeedPasskeyAsync(Guid userId, byte[] credentialId, byte[] publicKey, uint signCount)
	{
		await using var seed = _fixture.CreateContext();
		seed.UserPasskeys.Add(new()
		{
			UserId = userId,
			CredentialId = credentialId,
			Data = new()
			{
				PublicKey = publicKey,
				CreatedAt = DateTimeOffset.UtcNow,
				SignCount = signCount,
				IsUserVerified = true,
				AttestationObject = [4],
				ClientDataJson = [5]
			}
		});
		await seed.SaveChangesAsync(Cancellation);
	}

	/// <summary>One of every child row the delete class removes: a claim, a role, a login, a token and a passkey.</summary>
	async Task<(NorseUser User, NorseRole Role)> SeedChildRowsAsync(string email)
	{
		var seeded = await _fixture.SeedUserAsync(email);
		var role = await SeedRoleAsync();
		await SeedClaimAsync(seeded.Id, "department", "sales");
		await SeedPasskeyAsync(seeded.Id, CredentialId(seeded.Id), [1, 2, 3], signCount: 1);
		await using var seed = _fixture.CreateContext();
		seed.UserRoles.Add(new() { UserId = seeded.Id, RoleId = role.Id });
		seed.UserLogins.Add(new() { UserId = seeded.Id, LoginProvider = "TestProvider", ProviderKey = LoginKey(seeded.Id) });
		seed.UserTokens.Add(new() { UserId = seeded.Id, LoginProvider = "TestProvider", Name = "refresh", Value = "alpha" });
		using (SubjectCryptoScope.Begin(seeded.Id))
			await seed.SaveChangesAsync(Cancellation);
		return (seeded, role);
	}

	async Task SeedRecoveryCodesAsync(Guid userId, string codes)
	{
		await using var seed = _fixture.CreateContext();
		seed.UserTokens.Add(new() { UserId = userId, LoginProvider = RecoveryCodeProvider, Name = RecoveryCodeName, Value = codes });
		using (SubjectCryptoScope.Begin(userId))
			await seed.SaveChangesAsync(Cancellation);
	}

	/// <summary>The real handler <c>SignInManager</c> drives, for <see cref="RelyingParty" />.</summary>
	static PasskeyHandler<NorseUser> PasskeyHandler(UserManager<NorseUser> manager) =>
		new(manager, Options.Create(new IdentityPasskeyOptions
		{
			ServerDomain = RelyingParty,
			ValidateOrigin = static context => ValueTask.FromResult(string.Equals(context.Origin, $"https://{RelyingParty}", StringComparison.Ordinal))
		}));

	static DefaultHttpContext AssertionHttpContext()
	{
		DefaultHttpContext http = new();
		http.Request.Scheme = "https";
		http.Request.Host = new(RelyingParty);
		return http;
	}

	static string Challenge(string requestOptionsJson)
	{
		using var options = JsonDocument.Parse(requestOptionsJson);
		return options.RootElement.GetProperty("challenge").GetString().ShouldNotBeNull();
	}

	/// <summary>The authenticator's P-256 public key as the COSE_Key a WebAuthn attestation carries (ES256, RFC 9053).</summary>
	static byte[] CosePublicKey(ECDsa authenticator)
	{
		var point = authenticator.ExportParameters(includePrivateParameters: false).Q;
		// {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
		return [0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, .. point.X!, 0x22, 0x58, 0x20, .. point.Y!];
	}

	/// <summary>A WebAuthn assertion for <paramref name="challenge" />, signed by the authenticator, as a browser posts it.</summary>
	static string SignAssertion(ECDsa authenticator, byte[] credentialId, Guid userId, string challenge, uint signCount)
	{
		byte[] counter = new byte[4];
		BinaryPrimitives.WriteUInt32BigEndian(counter, signCount);
		// rpIdHash, then flags (user present, user verified), then the counter.
		byte[] authenticatorData = [.. SHA256.HashData(Encoding.UTF8.GetBytes(RelyingParty)), 0x05, .. counter];
		var clientDataJson = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new Dictionary<string, object>
		{
			["type"] = "webauthn.get",
			["challenge"] = challenge,
			["origin"] = $"https://{RelyingParty}",
			["crossOrigin"] = false
		}));
		var signature = authenticator.SignData([.. authenticatorData, .. SHA256.HashData(clientDataJson)], HashAlgorithmName.SHA256,
			DSASignatureFormat.Rfc3279DerSequence);
		return JsonSerializer.Serialize(new Dictionary<string, object>
		{
			["id"] = Base64Url.EncodeToString(credentialId),
			["rawId"] = Base64Url.EncodeToString(credentialId),
			["type"] = "public-key",
			["response"] = new Dictionary<string, string>
			{
				["clientDataJSON"] = Base64Url.EncodeToString(clientDataJson),
				["authenticatorData"] = Base64Url.EncodeToString(authenticatorData),
				["signature"] = Base64Url.EncodeToString(signature),
				["userHandle"] = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(userId.ToString()))
			},
			["clientExtensionResults"] = new Dictionary<string, object>()
		});
	}
}
