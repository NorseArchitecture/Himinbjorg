using System.Data.Common;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Norse.Abstractions.Backend.Keys;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Store;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     <see cref="NorseUserStore" />, the explicit-write store (2026-10-24 explicit-writes plan Tasks 4.5-4.10), once per
///     provider, through the production registration: reads, baseline and create; the flush; the immediate
///     operations; child rows; and the manager's abandon hook.
/// </summary>
/// <remarks>
///     Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///     records: xUnit discovers them on each <see langword="sealed" /> provider class. Raw rows are read from
///     whichever table the model maps them to, so one body serves both providers' naming.
/// </remarks>
public abstract class NorseUserStoreSuite : IDisposable
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	/// <summary>
	///     Every <c>Supports*</c> probe <see cref="UserManager{TUser}" /> declares on .NET 11 RC2 (V1, read off the
	///     decompiled <c>Microsoft.Extensions.Identity.Core</c>). A probe added upstream fails the pin below and needs
	///     a ruling: implement the capability or refuse it, never inherit a silent <see langword="false" />.
	/// </summary>
	static readonly string[] _managerProbes =
	[
		nameof(UserManager<>.SupportsQueryableUsers),
		nameof(UserManager<>.SupportsUserAuthenticationTokens),
		nameof(UserManager<>.SupportsUserAuthenticatorKey),
		nameof(UserManager<>.SupportsUserClaim),
		nameof(UserManager<>.SupportsUserEmail),
		nameof(UserManager<>.SupportsUserLockout),
		nameof(UserManager<>.SupportsUserLogin),
		nameof(UserManager<>.SupportsUserPasskey),
		nameof(UserManager<>.SupportsUserPassword),
		nameof(UserManager<>.SupportsUserPhoneNumber),
		nameof(UserManager<>.SupportsUserRole),
		nameof(UserManager<>.SupportsUserSecurityStamp),
		nameof(UserManager<>.SupportsUserTwoFactor),
		nameof(UserManager<>.SupportsUserTwoFactorRecoveryCodes)
	];

	readonly IdentityFixture _fixture;
	readonly List<NorseIdentityDbContext> _contexts = [];

	/// <summary>Binds the suite to the provider's shared fixture.</summary>
	/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
	protected NorseUserStoreSuite(IdentityFixture fixture) =>
		_fixture = fixture;

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <summary>The current test's cancellation token.</summary>
	protected static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	/// <inheritdoc />
	public void Dispose()
	{
		foreach (var context in _contexts)
			context.Dispose();
		GC.SuppressFinalize(this);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected void Store_supports_every_capability_the_manager_probes()
	{
		_fixture.SkipUnlessAvailable();
		_fixture.CreateUserStore().ShouldBeOfType<NorseUserStore>();
		var userManager = _fixture.CreateUserManager();

		var probes = typeof(UserManager<NorseUser>)
			.GetProperties()
			.Where(static property => property.Name.StartsWith("Supports", StringComparison.Ordinal))
			.ToDictionary(static property => property.Name, property => property.GetValue(userManager) is true);

		probes.Keys.Order(StringComparer.Ordinal).ShouldBe(_managerProbes);
		probes
			.Where(static probe => probe.Key != nameof(UserManager<>.SupportsQueryableUsers))
			.ShouldAllBe(static probe => probe.Value);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Create_inserts_both_fragments_in_one_transaction_and_registers_a_baseline()
	{
		_fixture.SkipUnlessAvailable();
		TransactionRecorder transactions = new();
		CommandRecorder commands = new();
		await using var context = _fixture.CreateContext(transactions, commands);
		using NorseUserStore store = new(context, new());
		var id = Guid.CreateVersion7();
		var lookup = $"create-lookup-{id:N}";
		NorseUser user = new()
		{
			Id = id,
			UserName = "create-both-fragments@example.com",
			Email = "create-both-fragments@example.com",
			NormalizedUserName = lookup,
			NormalizedEmail = lookup,
			SecurityStamp = "CREATEBOTHFRAGMENTSSTAMP23456789"
		};

		IdentityResult result;
		using (SubjectCryptoScope.Begin(id))
			result = await store.CreateAsync(user, Cancellation);

		result.Succeeded.ShouldBeTrue();
		var transaction = transactions.Started.ShouldHaveSingleItem();
		transactions.Committed.ShouldBe(1);
		commands.Executed.ShouldNotBeEmpty();
		commands.Executed.ShouldAllBe(command => command.Transaction == transaction,
			"every statement runs inside the store's one explicit transaction");
		var (principal, fragment) = Tables(context);
		var sql = string.Join('\n', commands.Executed.Select(static command => command.Sql));
		sql.ShouldContain(Delimited(context, principal));
		sql.ShouldContain(Delimited(context, fragment));
		context.ChangeTracker.Entries().ShouldBeEmpty("the insert leaves nothing tracked");
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await RowCountAsync(verify, principal, id)).ShouldBe(1);
		(await RowCountAsync(verify, fragment, id)).ShouldBe(1);
		NorseUserStore.TryGetBaseline(user, out var baseline).ShouldBeTrue();
		baseline.ShouldBe(UserBaseline.Capture(user));
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task FindById_returns_the_whole_entity_including_credentials()
	{
		// The pre-swap UserStore-derived store's projection returned seven columns, and a write through it persisted
		// C# defaults over everything else (spec §1, item 3). Every column of both fragments must come back as stored.
		_fixture.SkipUnlessAvailable();
		var userManager = _fixture.CreateUserManager();
		var lockoutEnd = new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero);
		NorseUser user = new()
		{
			UserName = "find-whole-entity@example.com",
			Email = "find-whole-entity@example.com",
			EmailConfirmed = true,
			PhoneNumber = "+15550100",
			PhoneNumberConfirmed = true,
			TwoFactorEnabled = true,
			LockoutEnd = lockoutEnd,
			AccessFailedCount = 2
		};
		(await userManager.CreateAsync(user, "Correct-Horse-1!")).Succeeded.ShouldBeTrue();

		var found = (await _fixture.CreateUserStore().FindByIdAsync(user.Id.ToString(), Cancellation)).ShouldNotBeNull();

		found.ShouldNotBeSameAs(user);
		found.ShouldSatisfyAllConditions(
			() => found.Id.ShouldBe(user.Id),
			() => found.UserName.ShouldBe("find-whole-entity@example.com"),
			() => found.Email.ShouldBe("find-whole-entity@example.com"),
			() => found.EmailConfirmed.ShouldBeTrue(),
			() => found.PhoneNumber.ShouldBe("+15550100"),
			() => found.PhoneNumberConfirmed.ShouldBeTrue(),
			() => found.TwoFactorEnabled.ShouldBeTrue(),
			() => found.LockoutEnabled.ShouldBeTrue(),
			() => found.ConcurrencyStamp.ShouldBe(user.ConcurrencyStamp),
			() => found.PasswordHash.ShouldNotBeNull().ShouldBe(user.PasswordHash),
			() => found.SecurityStamp.ShouldNotBeNull().ShouldBe(user.SecurityStamp),
			() => found.NormalizedUserName.ShouldNotBeNull().ShouldBe(user.NormalizedUserName),
			() => found.NormalizedEmail.ShouldBe(user.NormalizedEmail),
			() => found.LockoutEnd.ShouldBe(lockoutEnd),
			() => found.AccessFailedCount.ShouldBe(2));
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task FindById_returns_null_for_a_missing_user()
	{
		_fixture.SkipUnlessAvailable();
		using var store = _fixture.CreateUserStore();

		(await store.FindByIdAsync(Guid.NewGuid().ToString(), Cancellation)).ShouldBeNull();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Every_store_read_registers_a_baseline()
	{
		_fixture.SkipUnlessAvailable();
		var user = await _fixture.SeedUserAsync("every-read-baseline@example.com", "+15550101");
		var loginKey = $"every-read-{user.Id:N}";
		byte[] credentialId = [.. user.Id.ToByteArray(), 1];
		await using (var seed = _fixture.CreateContext())
		{
			seed.Set<NorseUserLogin>().Add(new() { UserId = user.Id, LoginProvider = "TestProvider", ProviderKey = loginKey });
			seed.Set<NorseUserPasskey>().Add(new()
			{
				UserId = user.Id,
				CredentialId = credentialId,
				Data = new()
				{
					PublicKey = [1, 2, 3],
					Name = "every-read",
					CreatedAt = DateTimeOffset.UtcNow,
					SignCount = 7,
					AttestationObject = [4],
					ClientDataJson = [5]
				}
			});
			await seed.SaveChangesAsync(Cancellation);
		}

		var store = _fixture.CreateUserStore();
		var emails = (IUserEmailStore<NorseUser>)store;
		var logins = (IUserLoginStore<NorseUser>)store;
		var passkeys = (IUserPasskeyStore<NorseUser>)store;
		NorseUser?[] reads =
		[
			await store.FindByIdAsync(user.Id.ToString(), Cancellation),
			await store.FindByNameAsync(user.NormalizedUserName.ShouldNotBeNull(), Cancellation),
			await emails.FindByEmailAsync(user.NormalizedEmail.ShouldNotBeNull(), Cancellation),
			await logins.FindByLoginAsync("TestProvider", loginKey, Cancellation),
			await passkeys.FindByPasskeyIdAsync(credentialId, Cancellation)
		];

		reads.Distinct().Count().ShouldBe(reads.Length, "each read hands out its own instance");
		foreach (var read in reads)
		{
			read.ShouldNotBeNull().Id.ShouldBe(user.Id);
			read.PhoneNumber.ShouldBe("+15550101");
			NorseUserStore.TryGetBaseline(read, out var baseline).ShouldBeTrue();
			baseline.ShouldBe(UserBaseline.Capture(read));
		}

		// The as-read passkey state, on two different instances through the two passkey reads.
		var listed = reads[0].ShouldNotBeNull();
		(await passkeys.GetPasskeysAsync(listed, Cancellation)).ShouldHaveSingleItem().SignCount.ShouldBe(7u);
		NorseUserStore.TryGetBaseline(listed, out var listedBaseline).ShouldBeTrue();
		listedBaseline.PasskeySignCount(credentialId).ShouldBe(7u);
		var found = reads[1].ShouldNotBeNull();
		(await passkeys.FindPasskeyAsync(found, credentialId, Cancellation)).ShouldNotBeNull().Name.ShouldBe("every-read");
		NorseUserStore.TryGetBaseline(found, out var foundBaseline).ShouldBeTrue();
		foundBaseline.PasskeySignCount(credentialId).ShouldBe(7u);
		NorseUserStore.TryGetBaseline(reads[2].ShouldNotBeNull(), out var unlisted).ShouldBeTrue();
		unlisted.PasskeySignCount(credentialId).ShouldBeNull("only a passkey read records passkey state");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Baseline_survives_a_scope_change()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("baseline-scope@example.com", "+15550102");
		byte[] credentialId = [.. seeded.Id.ToByteArray(), 2];
		await using (var seed = _fixture.CreateContext())
		{
			seed.Set<NorseUserPasskey>().Add(new()
			{
				UserId = seeded.Id,
				CredentialId = credentialId,
				Data = new()
				{
					PublicKey = [1],
					CreatedAt = DateTimeOffset.UtcNow,
					SignCount = 3,
					AttestationObject = [2],
					ClientDataJson = [3]
				}
			});
			await seed.SaveChangesAsync(Cancellation);
		}

		NorseUser user;
		using (var first = _fixture.CreateOwnedScope())
			user = (await first.ServiceProvider.GetRequiredService<IUserStore<NorseUser>>()
				.FindByIdAsync(seeded.Id.ToString(), Cancellation)).ShouldNotBeNull();
		// The manager mutates the instance before it updates; the baseline keeps what was read.
		user.PhoneNumber = "+15550199";

		using var second = _fixture.CreateOwnedScope();
		var passkeys = (IUserPasskeyStore<NorseUser>)second.ServiceProvider.GetRequiredService<IUserStore<NorseUser>>();
		await passkeys.GetPasskeysAsync(user, Cancellation);

		NorseUserStore.TryGetBaseline(user, out var baseline).ShouldBeTrue("the first scope is gone, the baseline is not");
		baseline.PhoneNumber.ShouldBe("+15550102");
		baseline.ConcurrencyStamp.ShouldBe(seeded.ConcurrencyStamp);
		baseline.PasskeySignCount(credentialId).ShouldBe(3u, "a second scope's store extends the same baseline");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Update_of_an_instance_without_a_baseline_is_refused()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("no-baseline@example.com");
		var read = (await _fixture.CreateUserStore().FindByIdAsync(seeded.Id.ToString(), Cancellation)).ShouldNotBeNull();
		// A faithful copy of a real row, as deserialization or a mapper would produce: the values are right, but
		// this store never handed it out.
		NorseUser copy = new()
		{
			Id = read.Id,
			UserName = read.UserName,
			NormalizedUserName = read.NormalizedUserName,
			Email = read.Email,
			NormalizedEmail = read.NormalizedEmail,
			SecurityStamp = read.SecurityStamp,
			ConcurrencyStamp = read.ConcurrencyStamp,
			LockoutEnabled = read.LockoutEnabled
		};
		NorseUser handBuilt = new() { Id = Guid.CreateVersion7(), UserName = "hand-built@example.com", Email = "hand-built@example.com" };

		var throughManager = await Should.ThrowAsync<InvalidOperationException>(() => _fixture.CreateUserManager().UpdateAsync(copy));
		var throughStore = await Should.ThrowAsync<InvalidOperationException>(() =>
			_fixture.CreateUserStore().UpdateAsync(handBuilt, Cancellation));

		throughManager.Message.ShouldContain("baseline");
		throughStore.Message.ShouldContain("baseline");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task GetUsersInRole_and_GetUsersForClaim_are_refused()
	{
		_fixture.SkipUnlessAvailable();
		var userManager = _fixture.CreateUserManager();

		var inRole = await Should.ThrowAsync<NotSupportedException>(() => userManager.GetUsersInRoleAsync("any-role"));
		var forClaim = await Should.ThrowAsync<NotSupportedException>(() =>
			userManager.GetUsersForClaimAsync(new Claim("any-type", "any-value")));

		inRole.Message.ShouldContain("subject-singular");
		forClaim.Message.ShouldContain("subject-singular");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task DeleteAsync_is_refused_naming_ShredAsync()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("delete-refused@example.com");
		var (seedContext, _) = await _fixture.CreateScopeAsync();
		await ErasureServiceSuite.SeedOpenIddictRowsAsync(seedContext, seeded.Id);
		var userManager = _fixture.CreateUserManager();
		var reloaded = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		var refusal = await Should.ThrowAsync<NotSupportedException>(() => userManager.DeleteAsync(reloaded));

		refusal.Message.ShouldContain(nameof(ErasureService.ShredAsync));
		var (context, keyStore) = await _fixture.CreateScopeAsync();
		(await context.Users.AnyAsync(u => u.Id == seeded.Id, Cancellation)).ShouldBeTrue("the row stays");
		(await keyStore.GetAsync(seeded.Id, Cancellation))
			.Match(static _ => "available", static _ => "destroyed", static () => "missing")
			.ShouldBe("available", "the key stays");
		(await ErasureServiceSuite.OpenIddictRowsAsync(context, seeded.Id))
			.ShouldBe(2, "the subject's authorization and token stay");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected void QueryableUserStore_is_not_implemented()
	{
		// An IQueryable<NorseUser> door invites list-shaped decrypted reads (PII spec §4.1, subject-singular law).
		_fixture.SkipUnlessAvailable();
		var store = _fixture.CreateUserStore();
		var userManager = _fixture.CreateUserManager();

		store.ShouldBeOfType<NorseUserStore>().ShouldNotBeAssignableTo<IQueryableUserStore<NorseUser>>();
		userManager.SupportsQueryableUsers.ShouldBeFalse();
		Should.Throw<NotSupportedException>(() => userManager.Users);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task No_op_update_issues_no_users_statement_and_writes_no_history()
	{
		// SQL Server versions every UPDATE that touches a row, equal values or not (PoC G2): the only no-op guard
		// there is that the statement is never issued.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("no-op-update@example.com", "+15550110");
		var (userManager, commands) = RecordingManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		commands.Executed.Clear();

		(await userManager.UpdateAsync(user)).Succeeded.ShouldBeTrue();

		commands.Executed.ShouldNotContain(static command => command.Sql.Contains("UPDATE", StringComparison.OrdinalIgnoreCase),
			"no column changed, so no statement writes anything");
		user.ConcurrencyStamp.ShouldBe(seeded.ConcurrencyStamp);
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Password_change_writes_no_users_history()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithPasswordAsync("password-change@example.com");
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		(await userManager.ChangePasswordAsync(user, Password, "Battery-Staple-2!")).Succeeded.ShouldBeTrue();

		var reread = await RereadAsync(seeded.Id);
		(await _fixture.CreateUserManager().CheckPasswordAsync(reread, "Battery-Staple-2!")).ShouldBeTrue();
		reread.SecurityStamp.ShouldNotBe(seeded.SecurityStamp, "a password change rotates the stamp");
		reread.ConcurrencyStamp.ShouldBe(seeded.ConcurrencyStamp, "no users column changed");
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Stamp_rotation_writes_no_users_history()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("stamp-rotation@example.com");
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		(await userManager.UpdateSecurityStampAsync(user)).Succeeded.ShouldBeTrue();

		var reread = await RereadAsync(seeded.Id);
		reread.SecurityStamp.ShouldNotBe(seeded.SecurityStamp);
		reread.SecurityStamp.ShouldBe(user.SecurityStamp);
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Phone_change_writes_one_version_and_preserves_other_ciphertext_bytes()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("phone-change@example.com", "+15550111");
		var (verify, _) = await _fixture.CreateScopeAsync();
		var emailBefore = await RawUsersColumnAsync(verify, nameof(NorseUser.Email), seeded.Id);
		var userNameBefore = await RawUsersColumnAsync(verify, nameof(NorseUser.UserName), seeded.Id);
		var phoneBefore = await RawUsersColumnAsync(verify, nameof(NorseUser.PhoneNumber), seeded.Id);
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		(await userManager.SetPhoneNumberAsync(user, "+15550112")).Succeeded.ShouldBeTrue();

		(await RawUsersColumnAsync(verify, nameof(NorseUser.Email), seeded.Id)).ShouldBe(emailBefore,
			"an unchanged ciphertext column never appears in the SET clause");
		(await RawUsersColumnAsync(verify, nameof(NorseUser.UserName), seeded.Id)).ShouldBe(userNameBefore);
		(await RawUsersColumnAsync(verify, nameof(NorseUser.PhoneNumber), seeded.Id)).ShouldNotBe(phoneBefore);
		var reread = await RereadAsync(seeded.Id);
		reread.PhoneNumber.ShouldBe("+15550112");
		reread.ConcurrencyStamp.ShouldBe(user.ConcurrencyStamp);
		reread.ConcurrencyStamp.ShouldNotBe(seeded.ConcurrencyStamp);
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(1);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Stale_concurrency_stamp_returns_ConcurrencyFailure_and_restores_the_instance()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("stale-stamp@example.com", "+15550120");
		var winnerManager = _fixture.CreateUserManager();
		var loserManager = _fixture.CreateUserManager();
		var winner = (await winnerManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var loser = (await loserManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var asRead = UserBaseline.Capture(loser);
		(await winnerManager.SetPhoneNumberAsync(winner, "+15550121")).Succeeded.ShouldBeTrue();

		var result = await loserManager.SetPhoneNumberAsync(loser, "+15550122");

		result.Succeeded.ShouldBeFalse();
		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(nameof(IdentityErrorDescriber.ConcurrencyFailure));
		UserBaseline.Capture(loser).ShouldBe(asRead, "a failed operation leaves the instance exactly as read");
		NorseUserStore.TryGetBaseline(loser, out var baseline).ShouldBeTrue();
		baseline.ShouldBe(asRead, "a failure never refreshes the baseline");
		var reread = await RereadAsync(seeded.Id);
		reread.PhoneNumber.ShouldBe("+15550121");
		reread.SecurityStamp.ShouldBe(winner.SecurityStamp);
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(1, "only the winner versioned the row");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Concurrent_password_changes_one_succeeds_one_ConcurrencyFailure()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithPasswordAsync("concurrent-password@example.com");
		var firstManager = _fixture.CreateUserManager();
		var secondManager = _fixture.CreateUserManager();
		var first = (await firstManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var second = (await secondManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		var results = await Task.WhenAll(
			Task.Run(() => firstManager.ChangePasswordAsync(first, Password, "First-Horse-2!"), Cancellation),
			Task.Run(() => secondManager.ChangePasswordAsync(second, Password, "Second-Horse-3!"), Cancellation));

		results.Count(static result => result.Succeeded).ShouldBe(1);
		results
			.Single(static result => !result.Succeeded)
			.Errors.ShouldHaveSingleItem().Code.ShouldBe(nameof(IdentityErrorDescriber.ConcurrencyFailure));
		var (winner, loser, winningPassword) = results[0].Succeeded ?
			(first, second, "First-Horse-2!") :
			(second, first, "Second-Horse-3!");
		loser.PasswordHash.ShouldBe(seeded.PasswordHash, "the loser is restored to its as-read hash");
		var reread = await RereadAsync(seeded.Id);
		reread.PasswordHash.ShouldBe(winner.PasswordHash);
		reread.SecurityStamp.ShouldBe(winner.SecurityStamp);
		(await _fixture.CreateUserManager().CheckPasswordAsync(reread, winningPassword)).ShouldBeTrue();
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Credential_CAS_failure_after_users_statement_rolls_back_everything()
	{
		// The rotation moves only the credentials fragment, so the loser's users statement still matches its stamp;
		// its credentials CAS is what fails, after the users row was already updated inside the transaction.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("credential-cas@example.com", "+15550130");
		var rotatorManager = _fixture.CreateUserManager();
		var loserManager = _fixture.CreateUserManager();
		var rotator = (await rotatorManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var loser = (await loserManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var asRead = UserBaseline.Capture(loser);
		(await rotatorManager.UpdateSecurityStampAsync(rotator)).Succeeded.ShouldBeTrue();
		var (userManager, commands) = RecordingManager();

		var result = await userManager.SetPhoneNumberAsync(loser, "+15550131");

		result.Succeeded.ShouldBeFalse();
		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(nameof(IdentityErrorDescriber.ConcurrencyFailure));
		commands.Executed.Count(static command => command.Sql.Contains("UPDATE", StringComparison.OrdinalIgnoreCase))
			.ShouldBe(2, "the users statement ran and matched; the credentials CAS ran and did not");
		UserBaseline.Capture(loser).ShouldBe(asRead);
		var reread = await RereadAsync(seeded.Id);
		reread.PhoneNumber.ShouldBe("+15550130", "the users statement rolled back with the failed CAS");
		reread.ConcurrencyStamp.ShouldBe(seeded.ConcurrencyStamp);
		reread.SecurityStamp.ShouldBe(rotator.SecurityStamp);
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(0, "a rolled-back update commits no history");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Unique_index_race_rolls_back_and_maps_to_DuplicateUserName()
	{
		// A race past UserValidator, made deterministic: the racer's manager runs no validators, as if its check
		// ran before the holder's change committed. On PostgreSQL the violation aborts the transaction, so the
		// store must roll back before it reads anything.
		_fixture.SkipUnlessAvailable();
		var holder = await _fixture.SeedUserAsync("unique-race-holder@example.com");
		var seeded = await _fixture.SeedUserAsync("unique-race-racer@example.com", "+15550140");
		var userManager = _fixture.CreateUserManager();
		userManager.UserValidators.Clear();
		var racer = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var asRead = UserBaseline.Capture(racer);

		// The store's own mapping, so the username is assigned directly: SetEmailAsync answers the same race as
		// DuplicateEmail (spec §3.1), which Concurrent_change_to_same_email_one_succeeds_one_DuplicateEmail proves.
		racer.Email = "unique-race-holder@example.com";
		racer.UserName = "unique-race-holder@example.com";

		var result = await userManager.UpdateAsync(racer);

		result.Succeeded.ShouldBeFalse();
		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(nameof(IdentityErrorDescriber.DuplicateUserName));
		UserBaseline.Capture(racer).ShouldBe(asRead);
		var reread = await RereadAsync(seeded.Id);
		reread.Email.ShouldBe("unique-race-racer@example.com");
		reread.UserName.ShouldBe("unique-race-racer@example.com");
		reread.NormalizedUserName.ShouldBe(seeded.NormalizedUserName);
		reread.ConcurrencyStamp.ShouldBe(seeded.ConcurrencyStamp);
		(await RereadAsync(holder.Id)).Email.ShouldBe("unique-race-holder@example.com");
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Write_through_GetUserAsync_preserves_PasswordHash_EmailConfirmed_LockoutEnabled()
	{
		// The pre-swap UserStore-derived store's projection read seven columns, and a write through what it returned
		// persisted C# defaults over the rest (spec §1, item 3).
		_fixture.SkipUnlessAvailable();
		var seedManager = _fixture.CreateUserManager();
		NorseUser seeded = new()
		{
			UserName = "get-user-write@example.com",
			Email = "get-user-write@example.com",
			EmailConfirmed = true
		};
		(await seedManager.CreateAsync(seeded, Password)).Succeeded.ShouldBeTrue();
		var userManager = _fixture.CreateUserManager();
		ClaimsPrincipal principal = new(new ClaimsIdentity(
			[new Claim(userManager.Options.ClaimsIdentity.UserIdClaimType, seeded.Id.ToString())], "Test"));
		var user = (await userManager.GetUserAsync(principal)).ShouldNotBeNull();

		(await userManager.SetPhoneNumberAsync(user, "+15550150")).Succeeded.ShouldBeTrue();

		var reread = await RereadAsync(seeded.Id);
		reread.ShouldSatisfyAllConditions(
			() => reread.PhoneNumber.ShouldBe("+15550150"),
			() => reread.PasswordHash.ShouldBe(seeded.PasswordHash),
			() => reread.EmailConfirmed.ShouldBeTrue(),
			() => reread.LockoutEnabled.ShouldBeTrue());
		(await _fixture.CreateUserManager().CheckPasswordAsync(reread, Password)).ShouldBeTrue();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Repeated_updates_on_one_instance_diff_against_the_last_commit()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("repeated-updates@example.com", "+15550160");
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var (verify, _) = await _fixture.CreateScopeAsync();

		(await userManager.SetPhoneNumberAsync(user, "+15550161")).Succeeded.ShouldBeTrue();
		NorseUserStore.TryGetBaseline(user, out var afterFirst).ShouldBeTrue();
		afterFirst.ShouldBe(UserBaseline.Capture(user), "a successful flush rebaselines to what it committed");
		(await userManager.SetPhoneNumberAsync(user, "+15550162")).Succeeded.ShouldBeTrue();
		var stampAfterSecond = user.ConcurrencyStamp;
		(await userManager.UpdateAsync(user)).Succeeded.ShouldBeTrue();

		user.ConcurrencyStamp.ShouldBe(stampAfterSecond, "the last update changed nothing, so wrote nothing");
		NorseUserStore.TryGetBaseline(user, out var baseline).ShouldBeTrue();
		baseline.ShouldBe(UserBaseline.Capture(user));
		var reread = await RereadAsync(seeded.Id);
		reread.PhoneNumber.ShouldBe("+15550162");
		reread.ConcurrencyStamp.ShouldBe(stampAfterSecond);
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(2, "two changes, two versions, and the no-op none");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Flush_outside_a_crypto_scope_throws_from_the_protector()
	{
		// V2: encryption now happens in the store's own statements, not in SaveChanges, so the manager's scope must
		// wrap the flush. Called on the store directly, with no scope, the protector refuses.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("flush-no-scope@example.com", "+15550170");
		var store = _fixture.CreateUserStore();
		var user = (await store.FindByIdAsync(seeded.Id.ToString(), Cancellation)).ShouldNotBeNull();
		var asRead = UserBaseline.Capture(user);
		user.PhoneNumber = "+15550171";

		var refusal = await Should.ThrowAsync<InvalidOperationException>(() => store.UpdateAsync(user, Cancellation));

		refusal.ToString().ShouldContain(nameof(SubjectCryptoScope));
		UserBaseline.Capture(user).ShouldBe(asRead, "a failure before commit restores the instance");
		(await RereadAsync(seeded.Id)).PhoneNumber.ShouldBe("+15550170");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Failed_password_writes_no_users_history()
	{
		// Himinbjörg#47's exit criterion, and the flip of TemporalIdentityVersioningSuite's former pin
		// (A_failed_password_attempt_currently_versions_users): the stock store's blanket write versioned users on
		// every wrong password; the increment is one statement on user_credentials and never touches users.
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithPasswordAsync("failed-password@example.com");
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var signInManager = _fixture.CreateSignInManager(userManager);

		var result = await signInManager.CheckPasswordSignInAsync(user, "wrong-password", lockoutOnFailure: true);

		result.Succeeded.ShouldBeFalse();
		result.IsLockedOut.ShouldBeFalse();
		user.AccessFailedCount.ShouldBe(1, "the instance takes the count the increment returned");
		NorseUserStore.TryGetBaseline(user, out var baseline).ShouldBeTrue();
		baseline.AccessFailedCount.ShouldBe(1, "and so does its baseline, so the following update has nothing to write");
		var reread = await RereadAsync(seeded.Id);
		reread.AccessFailedCount.ShouldBe(1);
		reread.ConcurrencyStamp.ShouldBe(seeded.ConcurrencyStamp);
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(0, "a wrong password never mints a users history row");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Lockout_writes_no_users_history()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithPasswordAsync("lockout@example.com");
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var signInManager = _fixture.CreateSignInManager(userManager);
		var threshold = userManager.Options.Lockout.MaxFailedAccessAttempts;

		List<SignInResult> results = [];
		for (var attempt = 0; attempt < threshold; attempt++)
			results.Add(await signInManager.CheckPasswordSignInAsync(user, "wrong-password", lockoutOnFailure: true));

		results.SkipLast(1).ShouldAllBe(static result => !result.Succeeded && !result.IsLockedOut);
		results[^1].IsLockedOut.ShouldBeTrue("the attempt that reaches the threshold locks the account");
		var reread = await RereadAsync(seeded.Id);
		(await _fixture.CreateUserManager().IsLockedOutAsync(reread)).ShouldBeTrue();
		reread.AccessFailedCount.ShouldBe(0, "a lockout resets the count");
		reread.ConcurrencyStamp.ShouldBe(seeded.ConcurrencyStamp);
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(0, "lockout churn lives in the credentials fragment");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Concurrent_failures_below_threshold_lose_no_increment()
	{
		// Every request reads the user (count 0) before any fails, and all of them meet at the increment, so an
		// instance-based write would land 1 every time. The database's own +1 must land every one.
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithPasswordAsync("concurrent-below@example.com");
		var participants = _fixture.CreateUserManager().Options.Lockout.MaxFailedAccessAttempts - 1;

		var (results, rendezvous) = await ConcurrentFailuresAsync(seeded.Id, participants);

		rendezvous.Arrived.ShouldBe(participants, "every request reached the increment before any ran it");
		results.ShouldAllBe(static result => !result.Succeeded && !result.IsLockedOut);
		var reread = await RereadAsync(seeded.Id);
		reread.AccessFailedCount.ShouldBe(participants);
		reread.LockoutEnd.ShouldBeNull();
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Concurrent_failures_across_threshold_lock_the_account()
	{
		// Exactly the threshold's worth of concurrent failures from 0: each gets a distinct count 1..N, so exactly
		// one -- the one that reads N -- takes the lockout branch. No reset can intervene before it.
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithPasswordAsync("concurrent-across@example.com");
		var participants = _fixture.CreateUserManager().Options.Lockout.MaxFailedAccessAttempts;

		var (results, rendezvous) = await ConcurrentFailuresAsync(seeded.Id, participants);

		rendezvous.Arrived.ShouldBe(participants);
		results.Count(static result => result.IsLockedOut).ShouldBe(1);
		results.ShouldAllBe(static result => !result.Succeeded);
		var reread = await RereadAsync(seeded.Id);
		(await _fixture.CreateUserManager().IsLockedOutAsync(reread)).ShouldBeTrue();
		reread.AccessFailedCount.ShouldBe(0, "the lockout's reset follows the last increment");
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Successful_sign_in_after_failures_resets_the_count_and_writes_no_users_history()
	{
		// The signing-in instance was read before the failures, so it still holds 0: only a database read of the
		// count (spec §4.5) sees that a reset is due, and only the staged reset intent writes it.
		_fixture.SkipUnlessAvailable();
		var seeded = await SeedWithPasswordAsync("reset-after-failures@example.com");
		var userManager = _fixture.CreateUserManager();
		var stale = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var failingManager = _fixture.CreateUserManager();
		var failing = (await failingManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var failingSignIn = _fixture.CreateSignInManager(failingManager);
		for (var attempt = 0; attempt < 2; attempt++)
			(await failingSignIn.CheckPasswordSignInAsync(failing, "wrong-password", lockoutOnFailure: true)).Succeeded
				.ShouldBeFalse();
		(await RereadAsync(seeded.Id)).AccessFailedCount.ShouldBe(2);
		stale.AccessFailedCount.ShouldBe(0);

		(await userManager.GetAccessFailedCountAsync(stale)).ShouldBe(2, "the count is read from the database");
		var result = await _fixture.CreateSignInManager(userManager)
			.CheckPasswordSignInAsync(stale, Password, lockoutOnFailure: true);

		result.Succeeded.ShouldBeTrue();
		var reread = await RereadAsync(seeded.Id);
		reread.AccessFailedCount.ShouldBe(0);
		reread.ConcurrencyStamp.ShouldBe(seeded.ConcurrencyStamp);
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Concurrent_redemption_of_one_code_exactly_one_succeeds()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("redeem-same@example.com");
		await SeedRecoveryCodesAsync(seeded.Id, "alpha;bravo;charlie");

		var (results, gate) = await ConcurrentRedemptionsAsync(seeded.Id, "alpha", "alpha");

		gate.Rendezvous.Arrived.ShouldBe(2, "both redemptions read the codes before either swapped");
		gate.Attempts.ShouldBe(2, "the winner swapped once; the loser's swap matched nothing");
		results.Count(static result => result.Succeeded).ShouldBe(1);
		results.Single(static result => !result.Succeeded)
			.Errors.ShouldHaveSingleItem().Code.ShouldBe(nameof(IdentityErrorDescriber.RecoveryCodeRedemptionFailed),
				"the loser re-read, found the code gone, and redeemed nothing");
		(await RecoveryCodesAsync(seeded.Id)).ShouldBe("bravo;charlie");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Concurrent_redemption_of_different_codes_neither_resurrects()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("redeem-different@example.com");
		await SeedRecoveryCodesAsync(seeded.Id, "alpha;bravo;charlie");

		var (results, gate) = await ConcurrentRedemptionsAsync(seeded.Id, "alpha", "bravo");

		gate.Rendezvous.Arrived.ShouldBe(2);
		gate.Attempts.ShouldBe(3, "the loser's first swap matched nothing; it re-read the winner's set and swapped again");
		results.ShouldAllBe(static result => result.Succeeded);
		(await RecoveryCodesAsync(seeded.Id)).ShouldBe("charlie", "neither redeemed code comes back");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Redemption_retry_exhaustion_throws()
	{
		// Before every swap a concurrent writer re-encrypts the same set (a fresh nonce, so fresh ciphertext): the
		// code stays present and every swap matches nothing, until the bound is reached.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("redeem-exhaustion@example.com");
		await SeedRecoveryCodesAsync(seeded.Id, "alpha;bravo");
		RecoveryCodeSaboteur saboteur = new(_fixture, seeded.Id, "alpha;bravo");
		var context = _fixture.CreateContext(saboteur);
		_contexts.Add(context);
		using var userManager = _fixture.CreateUserManager(new NorseUserStore(context, new()));
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		await Should.ThrowAsync<DbUpdateConcurrencyException>(() => userManager.RedeemTwoFactorRecoveryCodeAsync(user, "alpha"));

		saboteur.Fired.ShouldBe(5, "five swaps, each beaten, then the store gives up");
		(await RecoveryCodesAsync(seeded.Id)).ShouldBe("alpha;bravo", "nothing was redeemed");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task ReplaceClaim_persists_under_NoTracking()
	{
		// The pre-swap UserStore-derived store replaced the value on an untracked entity, and nothing ever wrote it.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("replace-claim@example.com");
		await SeedClaimAsync(seeded.Id, "department", "sales");
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		var result = await userManager.ReplaceClaimAsync(user, new("department", "sales"), new("department", "support"));

		result.Succeeded.ShouldBeTrue();
		(await ClaimsAsync(seeded.Id)).ShouldBe([("department", "support")]);
		(await RereadAsync(seeded.Id)).ConcurrencyStamp.ShouldBe(seeded.ConcurrencyStamp, "a claim is not a users column");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task ReplaceClaim_onto_an_existing_claim_converges_to_the_set()
	{
		// Claims are a set (ruled 2026-10-25): replacing A with a B the user already holds leaves exactly {B}. B's row
		// is untouched, so the only history is A's superseded version.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("replace-onto-existing@example.com");
		await SeedClaimAsync(seeded.Id, "department", "sales");
		await SeedClaimAsync(seeded.Id, "department", "support");
		await SeedClaimAsync(seeded.Id, "region", "emea");
		var supportRow = await ClaimIdAsync(seeded.Id, "department", "support");
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		var result = await userManager.ReplaceClaimAsync(user, new("department", "sales"), new("department", "support"));

		result.Succeeded.ShouldBeTrue();
		(await ClaimsAsync(seeded.Id)).ShouldBe([("department", "support"), ("region", "emea")], ignoreOrder: true);
		(await ClaimIdAsync(seeded.Id, "department", "support")).ShouldBe(supportRow, "the claim already held is not rewritten");
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await ClaimHistoryValuesAsync(verify, seeded.Id)).ShouldBe(["sales"], "only the replaced claim's version is history");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task ReplaceClaim_with_itself_keeps_the_claim_and_writes_nothing()
	{
		// PR #76 review: the converging delete matched the replacement's own row, so A -> A removed A.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("replace-claim-itself@example.com");
		await SeedClaimAsync(seeded.Id, "department", "sales");
		var salesRow = await ClaimIdAsync(seeded.Id, "department", "sales");
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		var result = await userManager.ReplaceClaimAsync(user, new("department", "sales"), new("department", "sales"));

		result.Succeeded.ShouldBeTrue();
		(await ClaimsAsync(seeded.Id)).ShouldBe([("department", "sales")]);
		(await ClaimIdAsync(seeded.Id, "department", "sales")).ShouldBe(salesRow, "the claim is not rewritten");
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await ClaimHistoryValuesAsync(verify, seeded.Id)).ShouldBeEmpty("an identical replacement is no change");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task ReplaceClaim_differing_only_in_type_casing_rewrites_the_claim()
	{
		// The self-match also reaches a type that differs only in case wherever the column's collation ignores case
		// (SQL Server's default): the rewrite must still land, not converge onto its own row and delete it.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("replace-claim-casing@example.com");
		await SeedClaimAsync(seeded.Id, "department", "sales");
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		var result = await userManager.ReplaceClaimAsync(user, new("department", "sales"), new("Department", "sales"));

		result.Succeeded.ShouldBeTrue();
		(await ClaimsAsync(seeded.Id)).ShouldBe([("Department", "sales")]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task SetToken_on_existing_token_persists_under_NoTracking()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("set-existing-token@example.com");
		await SeedTokenAsync(seeded.Id, "TestProvider", "access", "first");
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		var result = await userManager.SetAuthenticationTokenAsync(user, "TestProvider", "access", "second");

		result.Succeeded.ShouldBeTrue();
		(await TokenValuesAsync(seeded.Id, "TestProvider", "access")).ShouldBe(["second"]);
		var reread = await RereadAsync(seeded.Id);
		(await _fixture.CreateUserManager().GetAuthenticationTokenAsync(reread, "TestProvider", "access")).ShouldBe("second");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Passkey_rename_persists_under_NoTracking()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("passkey-rename@example.com");
		byte[] credentialId = [.. seeded.Id.ToByteArray(), 10];
		await SeedPasskeyAsync(seeded.Id, credentialId, signCount: 5, name: "old name");
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var passkey = (await userManager.GetPasskeyAsync(user, credentialId)).ShouldNotBeNull();
		passkey.Name = "new name";

		var result = await userManager.AddOrUpdatePasskeyAsync(user, passkey);

		result.Succeeded.ShouldBeTrue();
		var stored = (await PasskeyRowsAsync(credentialId)).ShouldHaveSingleItem();
		stored.Data.Name.ShouldBe("new name");
		stored.Data.SignCount.ShouldBe(5u);
		stored.Data.PublicKey.ShouldBe(_seededPublicKey);
		stored.UserId.ShouldBe(seeded.Id);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Claims_are_a_set_identical_add_is_a_no_op()
	{
		// Spec §4.6: insert-if-absent on (user_id, claim_type, claim_value_hash). Identity is exact-value, whatever
		// the collation, so a case variant is a second claim.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("claims-set@example.com");
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var again = (await _fixture.CreateUserManager().FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		(await userManager.AddClaimAsync(user, new("scope", "Admin"))).Succeeded.ShouldBeTrue();
		(await userManager.AddClaimAsync(user, new("scope", "Admin"))).Succeeded.ShouldBeTrue("a replay on one instance");
		(await _fixture.CreateUserManager().AddClaimAsync(again, new("scope", "Admin"))).Succeeded.ShouldBeTrue(
			"an identical add from a second instance");
		(await userManager.AddClaimAsync(user, new("scope", "admin"))).Succeeded.ShouldBeTrue();

		(await ClaimsAsync(seeded.Id)).ShouldBe([("scope", "Admin"), ("scope", "admin")], ignoreOrder: true);
		var reread = await RereadAsync(seeded.Id);
		(await _fixture.CreateUserManager().GetClaimsAsync(reread))
			.Select(static claim => (claim.Type, claim.Value))
			.ShouldBe([("scope", "Admin"), ("scope", "admin")], ignoreOrder: true);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Add_login_conflicting_with_another_user_fails_cleanly()
	{
		// A race past the manager's FindByLogin check, made deterministic: the racer stages the login straight on the
		// store, together with a users change, and updates. The owner's replay of its own login is success.
		_fixture.SkipUnlessAvailable();
		var owner = await _fixture.SeedUserAsync("login-owner@example.com");
		var seeded = await _fixture.SeedUserAsync("login-racer@example.com", "+15550180");
		var providerKey = $"login-conflict-{owner.Id:N}";
		UserLoginInfo login = new("TestProvider", providerKey, "Test");
		await using (var seed = _fixture.CreateContext())
		{
			seed.UserLogins.Add(new() { UserId = owner.Id, LoginProvider = login.LoginProvider, ProviderKey = providerKey });
			await seed.SaveChangesAsync(Cancellation);
		}

		CommandRecorder commands = new();
		var context = _fixture.CreateContext(commands);
		_contexts.Add(context);
		NorseUserStore store = new(context, new());
		using var userManager = _fixture.CreateUserManager(store);
		var racer = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var asRead = UserBaseline.Capture(racer);
		await store.AddLoginAsync(racer, login, Cancellation);
		racer.PhoneNumber = "+15550181";

		var result = await userManager.UpdateAsync(racer);

		result.Succeeded.ShouldBeFalse();
		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(nameof(IdentityErrorDescriber.LoginAlreadyAssociated));
		commands.Executed.ShouldContain(static command => command.Sql.Contains("INSERT", StringComparison.OrdinalIgnoreCase),
			"the store's insert itself met the conflict");
		UserBaseline.Capture(racer).ShouldBe(asRead);
		(await RereadAsync(seeded.Id)).PhoneNumber.ShouldBe("+15550180", "the users statement rolled back with the login");
		(await LoginOwnersAsync("TestProvider", providerKey)).ShouldBe([owner.Id]);
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await UserVersionsAsync(verify, seeded.Id)).ShouldBe(0);
		(await userManager.SetPhoneNumberAsync(racer, "+15550182")).Succeeded.ShouldBeTrue("the instance and context stay usable");

		var replayContext = _fixture.CreateContext();
		_contexts.Add(replayContext);
		NorseUserStore replayStore = new(replayContext, new());
		using var replayManager = _fixture.CreateUserManager(replayStore);
		var replayer = (await replayManager.FindByIdAsync(owner.Id.ToString())).ShouldNotBeNull();
		await replayStore.AddLoginAsync(replayer, login, Cancellation);
		(await replayManager.UpdateAsync(replayer)).Succeeded.ShouldBeTrue("a conflict with the same user is a replay");
		(await LoginOwnersAsync("TestProvider", providerKey)).ShouldBe([owner.Id]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Concurrent_same_key_token_creation_converges()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("token-converges@example.com");
		StatementGate gate = new(IsTokenUpsert, new(2));
		var requests = await GatedManagersAsync(seeded.Id, gate, 2);

		var results = await Task.WhenAll(requests.Select((request, index) => Task.Run(() =>
			request.Manager.SetAuthenticationTokenAsync(request.User, "TestProvider", "refresh", index is 0 ? "alpha" : "bravo"),
			Cancellation)));

		gate.Rendezvous.Arrived.ShouldBe(2, "both upserts were held until both had reached them");
		results.ShouldAllBe(static result => result.Succeeded);
		(await TokenValuesAsync(seeded.Id, "TestProvider", "refresh")).ShouldHaveSingleItem().ShouldBeOneOf("alpha", "bravo");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Concurrent_equivalent_passkey_enrollments_both_succeed_one_row()
	{
		// The same credential enrolled twice at once for the same user (a replayed attestation): the loser's insert
		// meets the winner's row, which is identical, so both succeed.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("passkey-equivalent@example.com");
		byte[] credentialId = [.. seeded.Id.ToByteArray(), 11];
		StatementGate gate = new(IsPasskeyInsert, new(2));
		var requests = await GatedManagersAsync(seeded.Id, gate, 2);

		var results = await Task.WhenAll(requests.Select(request => Task.Run(() =>
			request.Manager.AddOrUpdatePasskeyAsync(request.User, NewPasskey(credentialId, [7, 7, 7])), Cancellation)));

		gate.Rendezvous.Arrived.ShouldBe(2);
		results.ShouldAllBe(static result => result.Succeeded);
		var stored = (await PasskeyRowsAsync(credentialId)).ShouldHaveSingleItem();
		stored.UserId.ShouldBe(seeded.Id);
		stored.Data.PublicKey.ShouldBe([7, 7, 7]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Concurrent_conflicting_passkey_enrollments_one_succeeds_one_fails_cleanly()
	{
		_fixture.SkipUnlessAvailable();
		var first = await _fixture.SeedUserAsync("passkey-conflict-first@example.com");
		var second = await _fixture.SeedUserAsync("passkey-conflict-second@example.com");
		byte[] credentialId = [.. first.Id.ToByteArray(), 12];
		StatementGate gate = new(IsPasskeyInsert, new(2));
		var requests = (await GatedManagersAsync(first.Id, gate, 1)).Concat(await GatedManagersAsync(second.Id, gate, 1)).ToArray();
		var asRead = requests.Select(static request => UserBaseline.Capture(request.User)).ToArray();

		var results = await Task.WhenAll(requests.Select((request, index) => Task.Run(() =>
			request.Manager.AddOrUpdatePasskeyAsync(request.User, NewPasskey(credentialId, [(byte)index, 1])), Cancellation)));

		gate.Rendezvous.Arrived.ShouldBe(2);
		results.Count(static result => result.Succeeded).ShouldBe(1);
		var loser = results[0].Succeeded ?
			1 :
			0;
		results[loser].Errors.ShouldHaveSingleItem().Code.ShouldBe(NorseUserStore.PasskeyAlreadyRegisteredErrorCode);
		UserBaseline.Capture(requests[loser].User).ShouldBe(asRead[loser], "the loser is left exactly as read");
		var stored = (await PasskeyRowsAsync(credentialId)).ShouldHaveSingleItem();
		stored.UserId.ShouldBe(requests[1 - loser].User.Id);
		stored.Data.PublicKey.ShouldBe([(byte)(1 - loser), 1]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Out_of_order_passkey_assertion_fails_and_count_stays_newer()
	{
		// Spec §4.6: a delayed assertion that read 10 and proposes 11, after another wrote 12, matches zero rows.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("passkey-out-of-order@example.com");
		byte[] credentialId = [.. seeded.Id.ToByteArray(), 13];
		// Nameless, as most enrollments are: the update writes a null name into the document.
		await SeedPasskeyAsync(seeded.Id, credentialId, signCount: 10, name: null);
		var (newerManager, newer, newerPasskey) = await ReadForAssertionAsync(seeded.Id, credentialId);
		var (delayedManager, delayed, delayedPasskey) = await ReadForAssertionAsync(seeded.Id, credentialId);
		var asRead = UserBaseline.Capture(delayed);
		newerPasskey.SignCount = 12;
		(await newerManager.AddOrUpdatePasskeyAsync(newer, newerPasskey)).Succeeded.ShouldBeTrue();
		delayedPasskey.SignCount = 11;

		var result = await delayedManager.AddOrUpdatePasskeyAsync(delayed, delayedPasskey);

		result.Succeeded.ShouldBeFalse("PasskeySignInAsync answers SignInResult.Failed on a failed update (V7)");
		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(nameof(IdentityErrorDescriber.ConcurrencyFailure));
		UserBaseline.Capture(delayed).ShouldBe(asRead);
		(await PasskeyRowsAsync(credentialId)).ShouldHaveSingleItem().Data.SignCount.ShouldBe(12u);
		newerPasskey.SignCount = 13;
		(await newerManager.AddOrUpdatePasskeyAsync(newer, newerPasskey)).Succeeded.ShouldBeTrue(
			"the winner's baseline took the count it committed");
		var stored = (await PasskeyRowsAsync(credentialId)).ShouldHaveSingleItem();
		stored.Data.SignCount.ShouldBe(13u);
		stored.Data.Name.ShouldBeNull();
		stored.Data.PublicKey.ShouldBe(_seededPublicKey, "an assertion never rewrites the public key");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Passkey_removal_racing_an_assertion_fails_sign_in_and_does_not_reinsert()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("passkey-removal-race@example.com");
		byte[] credentialId = [.. seeded.Id.ToByteArray(), 14];
		await SeedPasskeyAsync(seeded.Id, credentialId, signCount: 3, name: "laptop");
		var (assertingManager, asserting, passkey) = await ReadForAssertionAsync(seeded.Id, credentialId);
		var removerManager = _fixture.CreateUserManager();
		var remover = (await removerManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		(await removerManager.RemovePasskeyAsync(remover, credentialId)).Succeeded.ShouldBeTrue();
		passkey.SignCount = 4;

		var result = await assertingManager.AddOrUpdatePasskeyAsync(asserting, passkey);

		result.Succeeded.ShouldBeFalse("PasskeySignInAsync answers SignInResult.Failed on a failed update (V7)");
		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(nameof(IdentityErrorDescriber.ConcurrencyFailure));
		(await PasskeyRowsAsync(credentialId)).ShouldBeEmpty("a removed credential is never re-inserted");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Concurrent_change_to_same_email_one_succeeds_one_DuplicateEmail()
	{
		// Both requests pass UserValidator (neither has committed), then meet at the credentials statement, so the
		// unique index on the username hash -- email uniqueness, given the CHECK -- decides (spec §3.1).
		_fixture.SkipUnlessAvailable();
		var first = await _fixture.SeedUserAsync("same-email-first@example.com", "+15550190");
		var second = await _fixture.SeedUserAsync("same-email-second@example.com", "+15550191");
		var target = "same-email-target@example.com";
		StatementGate gate = new(IsCredentialsUpdate, new(2));
		var requests = (await GatedManagersAsync(first.Id, gate, 1)).Concat(await GatedManagersAsync(second.Id, gate, 1)).ToArray();
		var asRead = requests.Select(static request => UserBaseline.Capture(request.User)).ToArray();

		var results = await Task.WhenAll(requests.Select(request => Task.Run(() =>
			request.Manager.SetEmailAsync(request.User, target), Cancellation)));

		gate.Rendezvous.Arrived.ShouldBe(2, "both passed validation and reached the credentials statement before either committed");
		results.Count(static result => result.Succeeded).ShouldBe(1);
		var loser = results[0].Succeeded ?
			1 :
			0;
		results[loser].Errors.ShouldHaveSingleItem().Code.ShouldBe(nameof(IdentityErrorDescriber.DuplicateEmail));
		UserBaseline.Capture(requests[loser].User).ShouldBe(asRead[loser], "the loser is left exactly as read");
		var winnerRow = await RereadAsync(requests[1 - loser].User.Id);
		winnerRow.Email.ShouldBe(target);
		winnerRow.UserName.ShouldBe(target);
		winnerRow.NormalizedUserName.ShouldBe(winnerRow.NormalizedEmail, "the CHECK holds");
		var loserRow = await RereadAsync(requests[loser].User.Id);
		loserRow.Email.ShouldBe(asRead[loser].Email);
		loserRow.UserName.ShouldBe(asRead[loser].Email);
		loserRow.NormalizedUserName.ShouldBe(loserRow.NormalizedEmail);
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await UserVersionsAsync(verify, requests[1 - loser].User.Id)).ShouldBe(1);
		(await UserVersionsAsync(verify, requests[loser].User.Id)).ShouldBe(0, "the loser's users statement rolled back");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Validation_failure_abandons_staged_intents_and_restores_the_instance()
	{
		// Spec §4.8: validation fails inside UpdateUserAsync, before Store.UpdateAsync, so only the manager can
		// abandon what the operation (and anything before it) staged on the instance.
		_fixture.SkipUnlessAvailable();
		var holder = await _fixture.SeedUserAsync("abandon-holder@example.com");
		var seeded = await _fixture.SeedUserAsync("abandon-user@example.com", "+15550200");
		var context = _fixture.CreateContext();
		_contexts.Add(context);
		NorseUserStore store = new(context, new());
		using var userManager = _fixture.CreateUserManager(store);
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var asRead = UserBaseline.Capture(user);
		await store.SetTokenAsync(user, "TestProvider", "abandoned", "staged", Cancellation);
		await store.SetPhoneNumberAsync(user, "+15550201", Cancellation);

		var result = await userManager.SetEmailAsync(user, holder.Email);

		result.Succeeded.ShouldBeFalse();
		result.Errors.ShouldContain(static error => error.Code == nameof(IdentityErrorDescriber.DuplicateEmail));
		UserBaseline.Capture(user).ShouldBe(asRead, "a validation failure leaves the instance exactly as read");
		NorseUserStore.TryGetBaseline(user, out var baseline).ShouldBeTrue();
		baseline.ShouldBe(asRead, "and leaves the baseline alone");
		(await userManager.SetPhoneNumberAsync(user, "+15550202")).Succeeded.ShouldBeTrue();
		(await TokenValuesAsync(seeded.Id, "TestProvider", "abandoned")).ShouldBeEmpty("the abandoned intent never rides a later flush");
		var reread = await RereadAsync(seeded.Id);
		reread.Email.ShouldBe("abandon-user@example.com");
		reread.PhoneNumber.ShouldBe("+15550202");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Child_intent_then_validation_failure_commits_nothing()
	{
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("child-then-invalid@example.com", "+15550210");
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		RefusingUserValidator refusing = new();
		userManager.UserValidators.Add(refusing);

		var result = await userManager.AddClaimAsync(user, new("scope", "abandoned"));

		result.Succeeded.ShouldBeFalse();
		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(RefusingUserValidator.Code);
		userManager.UserValidators.Remove(refusing);
		(await userManager.SetPhoneNumberAsync(user, "+15550211")).Succeeded.ShouldBeTrue();
		(await ClaimsAsync(seeded.Id)).ShouldBeEmpty("the claim was staged by a failed operation, so no flush ever writes it");
		var (verify, _) = await _fixture.CreateScopeAsync();
		(await ClaimHistoryValuesAsync(verify, seeded.Id)).ShouldBeEmpty();
		(await RereadAsync(seeded.Id)).PhoneNumber.ShouldBe("+15550211");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task AddToRoles_failing_partway_abandons_the_roles_staged_before_it()
	{
		// V5: the stock loop stages each role, then returns UserAlreadyInRole without ever reaching UpdateUserAsync.
		_fixture.SkipUnlessAvailable();
		var (staged, held) = await SeedRolesAsync();
		var seeded = await _fixture.SeedUserAsync("add-roles-partway@example.com");
		(await _fixture.CreateUserManager().AddToRoleAsync(await RereadAsync(seeded.Id), held)).Succeeded.ShouldBeTrue();
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var asRead = UserBaseline.Capture(user);

		var result = await userManager.AddToRolesAsync(user, [staged, held]);

		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(nameof(IdentityErrorDescriber.UserAlreadyInRole));
		UserBaseline.Capture(user).ShouldBe(asRead);
		(await userManager.SetPhoneNumberAsync(user, "+15550220")).Succeeded.ShouldBeTrue();
		(await _fixture.CreateUserManager().GetRolesAsync(user)).ShouldBe([held]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task RemoveFromRoles_failing_partway_abandons_the_removals_staged_before_it()
	{
		// V5: the stock loop stages each removal, then returns UserNotInRole without ever reaching UpdateUserAsync.
		_fixture.SkipUnlessAvailable();
		var (held, absent) = await SeedRolesAsync();
		var seeded = await _fixture.SeedUserAsync("remove-roles-partway@example.com");
		(await _fixture.CreateUserManager().AddToRoleAsync(await RereadAsync(seeded.Id), held)).Succeeded.ShouldBeTrue();
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();

		var result = await userManager.RemoveFromRolesAsync(user, [held, absent]);

		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(nameof(IdentityErrorDescriber.UserNotInRole));
		(await userManager.SetPhoneNumberAsync(user, "+15550221")).Succeeded.ShouldBeTrue();
		(await _fixture.CreateUserManager().GetRolesAsync(user)).ShouldBe([held]);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task ChangeEmail_refused_by_the_base_token_check_leaves_the_instance_as_read()
	{
		// V5: the override sets the username once the token verifies, then the base verifies again and may return
		// InvalidToken (a token expiring between the two checks) without reaching UpdateUserAsync.
		_fixture.SkipUnlessAvailable();
		var seeded = await _fixture.SeedUserAsync("change-email-second-check@example.com");
		var userManager = _fixture.CreateUserManager();
		userManager.RegisterTokenProvider(userManager.Options.Tokens.ChangeEmailTokenProvider, new OnceValidTokenProvider());
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		var asRead = UserBaseline.Capture(user);

		var result = await userManager.ChangeEmailAsync(user, "change-email-second-check-new@example.com", "token");

		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(nameof(IdentityErrorDescriber.InvalidToken));
		UserBaseline.Capture(user).ShouldBe(asRead, "the username the override set is put back");
		(await userManager.SetPhoneNumberAsync(user, "+15550222")).Succeeded.ShouldBeTrue();
		var reread = await RereadAsync(seeded.Id);
		reread.UserName.ShouldBe("change-email-second-check@example.com");
		reread.NormalizedUserName.ShouldBe(reread.NormalizedEmail);
	}

	/// <summary>The public key <see cref="SeedPasskeyAsync" /> stores.</summary>
	static readonly byte[] _seededPublicKey = [1, 2, 3];

	/// <summary>
	///     <paramref name="count" /> managers for one user, each on its own scope, context and instance, every context
	///     passing through <paramref name="gate" />.
	/// </summary>
	async Task<(NorseUserManager Manager, NorseUser User)[]> GatedManagersAsync(Guid userId, StatementGate gate, int count)
	{
		List<(NorseUserManager, NorseUser)> requests = [];
		for (var request = 0; request < count; request++)
		{
			var context = _fixture.CreateContext(gate);
			_contexts.Add(context);
			var userManager = _fixture.CreateUserManager(new NorseUserStore(context, new()));
			requests.Add((userManager, (await userManager.FindByIdAsync(userId.ToString())).ShouldNotBeNull()));
		}

		return [.. requests];
	}

	/// <summary>Reads the user and the passkey as <c>PasskeyHandler</c> does before it validates an assertion.</summary>
	async Task<(UserManager<NorseUser> Manager, NorseUser User, UserPasskeyInfo Passkey)> ReadForAssertionAsync(Guid userId,
		byte[] credentialId)
	{
		var userManager = _fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(userId.ToString())).ShouldNotBeNull();
		return (userManager, user, (await userManager.GetPasskeyAsync(user, credentialId)).ShouldNotBeNull());
	}

	/// <summary>A newly attested passkey, as <c>PasskeyHandler</c> builds one.</summary>
	static UserPasskeyInfo NewPasskey(byte[] credentialId, byte[] publicKey) =>
		new(credentialId, publicKey, DateTimeOffset.UtcNow, 0, ["internal"], true, false, false, [4], [5]);

	async Task SeedClaimAsync(Guid userId, string type, string value)
	{
		await using var seed = _fixture.CreateContext();
		seed.UserClaims.Add(new() { UserId = userId, ClaimType = type, ClaimValue = value });
		await seed.SaveChangesAsync(Cancellation);
	}

	async Task SeedTokenAsync(Guid userId, string loginProvider, string name, string value)
	{
		await using var seed = _fixture.CreateContext();
		seed.UserTokens.Add(new() { UserId = userId, LoginProvider = loginProvider, Name = name, Value = value });
		using (SubjectCryptoScope.Begin(userId))
			await seed.SaveChangesAsync(Cancellation);
	}

	async Task SeedPasskeyAsync(Guid userId, byte[] credentialId, uint signCount, string? name)
	{
		await using var seed = _fixture.CreateContext();
		seed.UserPasskeys.Add(new()
		{
			UserId = userId,
			CredentialId = credentialId,
			Data = new()
			{
				PublicKey = _seededPublicKey,
				Name = name,
				CreatedAt = DateTimeOffset.UtcNow,
				SignCount = signCount,
				AttestationObject = [4],
				ClientDataJson = [5]
			}
		});
		await seed.SaveChangesAsync(Cancellation);
	}

	/// <summary>The row id of one of the user's claims, as stored now.</summary>
	async Task<int> ClaimIdAsync(Guid userId, string type, string value)
	{
		await using var verify = _fixture.CreateContext();
		var claims = await verify.UserClaims
			.AsNoTracking()
			.Where(c => c.UserId == userId && c.ClaimType == type)
			.Select(static c => new { c.Id, c.ClaimValue })
			.ToListAsync(Cancellation);
		return claims.Single(c => string.Equals(c.ClaimValue, value, StringComparison.Ordinal)).Id;
	}

	/// <summary>The value of every superseded version of the user's claims the history holds.</summary>
	protected abstract Task<List<string>> ClaimHistoryValuesAsync(NorseIdentityDbContext context, Guid userId);

	/// <summary>The user's claims as stored now.</summary>
	async Task<List<(string?, string?)>> ClaimsAsync(Guid userId)
	{
		await using var verify = _fixture.CreateContext();
		var claims = await verify.UserClaims
			.AsNoTracking()
			.Where(c => c.UserId == userId)
			.Select(static c => new { c.ClaimType, c.ClaimValue })
			.ToListAsync(Cancellation);
		return [.. claims.Select(static c => (c.ClaimType, c.ClaimValue))];
	}

	/// <summary>Every stored value of one token key, decrypted.</summary>
	async Task<List<string?>> TokenValuesAsync(Guid userId, string loginProvider, string name)
	{
		await using var verify = _fixture.CreateContext();
		return await verify.UserTokens
			.AsNoTracking()
			.Where(t => t.UserId == userId && t.LoginProvider == loginProvider && t.Name == name)
			.Select(static t => t.Value)
			.ToListAsync(Cancellation);
	}

	/// <summary>Every stored row of one passkey credential.</summary>
	async Task<List<NorseUserPasskey>> PasskeyRowsAsync(byte[] credentialId)
	{
		await using var verify = _fixture.CreateContext();
		return await verify.UserPasskeys
			.AsNoTracking()
			.Where(p => p.CredentialId == credentialId)
			.ToListAsync(Cancellation);
	}

	/// <summary>The owners of one external login, as stored now.</summary>
	async Task<List<Guid>> LoginOwnersAsync(string loginProvider, string providerKey)
	{
		await using var verify = _fixture.CreateContext();
		return await verify.UserLogins
			.AsNoTracking()
			.Where(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey)
			.Select(static l => l.UserId)
			.ToListAsync(Cancellation);
	}

	/// <summary>Whether <paramref name="sql" /> is the token upsert, whichever provider spells it.</summary>
	static bool IsTokenUpsert(string sql) =>
		(sql.StartsWith("INSERT", StringComparison.OrdinalIgnoreCase) || sql.StartsWith("MERGE", StringComparison.OrdinalIgnoreCase)) &&
		(sql.Contains("user_tokens", StringComparison.Ordinal) || sql.Contains("[UserTokens]", StringComparison.Ordinal));

	/// <summary>
	///     Whether <paramref name="sql" /> is the passkey enrollment insert, whichever provider spells it (SQL Server's
	///     batch opens with <c>SET</c> options).
	/// </summary>
	static bool IsPasskeyInsert(string sql) =>
		sql.Contains("INSERT INTO", StringComparison.OrdinalIgnoreCase) &&
		(sql.Contains("user_passkeys", StringComparison.Ordinal) || sql.Contains("[UserPasskeys]", StringComparison.Ordinal));

	/// <summary>The password every <see cref="SeedWithPasswordAsync" /> user starts with.</summary>
	const string Password = "Correct-Horse-1!";

	/// <summary>Where stock Identity keeps the recovery-code set: its internal login provider and token name.</summary>
	const string RecoveryCodeProvider = "[AspNetUserStore]";

	const string RecoveryCodeName = "RecoveryCodes";

	/// <summary>
	///     <paramref name="participants" /> wrong-password sign-ins against one user, each on its own scope, context
	///     and instance, every instance read before any sign-in starts, all held at the increment until every one has
	///     reached it.
	/// </summary>
	async Task<(SignInResult[] Results, Rendezvous Rendezvous)> ConcurrentFailuresAsync(Guid userId, int participants)
	{
		Rendezvous rendezvous = new(participants);
		List<(NorseSignInManager SignIn, NorseUser User)> requests = [];
		for (var request = 0; request < participants; request++)
		{
			var context = _fixture.CreateContext(new StatementGate(static sql => sql.Contains("+ 1", StringComparison.Ordinal), rendezvous));
			_contexts.Add(context);
			var userManager = _fixture.CreateUserManager(new NorseUserStore(context, new()));
			requests.Add((_fixture.CreateSignInManager(userManager),
				(await userManager.FindByIdAsync(userId.ToString())).ShouldNotBeNull()));
		}

		var results = await Task.WhenAll(requests.Select(request => Task.Run(() =>
			request.SignIn.CheckPasswordSignInAsync(request.User, "wrong-password", lockoutOnFailure: true), Cancellation)));
		return (results, rendezvous);
	}

	/// <summary>
	///     One redemption per code, each on its own scope, context and instance, held after its read until both have
	///     read, so both swap against the same as-read set.
	/// </summary>
	async Task<(IdentityResult[] Results, StatementGate Gate)> ConcurrentRedemptionsAsync(Guid userId, params string[] codes)
	{
		StatementGate gate = new(IsTokenUpdate, new(codes.Length));
		List<(NorseUserManager Manager, NorseUser User, string Code)> requests = [];
		foreach (var code in codes)
		{
			var context = _fixture.CreateContext(gate);
			_contexts.Add(context);
			var userManager = _fixture.CreateUserManager(new NorseUserStore(context, new()));
			requests.Add((userManager, (await userManager.FindByIdAsync(userId.ToString())).ShouldNotBeNull(), code));
		}

		var results = await Task.WhenAll(requests.Select(request => Task.Run(() =>
			request.Manager.RedeemTwoFactorRecoveryCodeAsync(request.User, request.Code), Cancellation)));
		return (results, gate);
	}

	/// <summary>Stores <paramref name="codes" /> as the user's recovery-code set, encrypted as Identity stores it.</summary>
	async Task SeedRecoveryCodesAsync(Guid userId, string codes)
	{
		await using var seed = _fixture.CreateContext();
		seed.UserTokens.Add(new() { UserId = userId, LoginProvider = RecoveryCodeProvider, Name = RecoveryCodeName, Value = codes });
		using (SubjectCryptoScope.Begin(userId))
			await seed.SaveChangesAsync(Cancellation);
	}

	/// <summary>The user's recovery-code set as stored now, decrypted.</summary>
	async Task<string?> RecoveryCodesAsync(Guid userId)
	{
		await using var verify = _fixture.CreateContext();
		return await verify.UserTokens
			.AsNoTracking()
			.Where(t => t.UserId == userId && t.LoginProvider == RecoveryCodeProvider && t.Name == RecoveryCodeName)
			.Select(static t => t.Value)
			.SingleAsync(Cancellation);
	}

	/// <summary>Whether <paramref name="sql" /> is an <c>UPDATE</c> of the tokens table, whichever provider spells it.</summary>
	static bool IsTokenUpdate(string sql) =>
		sql.StartsWith("UPDATE", StringComparison.OrdinalIgnoreCase) &&
		(sql.Contains("user_tokens", StringComparison.Ordinal) || sql.Contains("[UserTokens]", StringComparison.Ordinal));

	/// <summary>
	///     Holds every participant at its first statement matching a predicate until all have reached it, and counts
	///     every matching statement. Later matches by the same participant pass straight through.
	/// </summary>
	sealed class StatementGate(Func<string, bool> matches, Rendezvous rendezvous) : DbCommandInterceptor
	{
		readonly HashSet<DbConnection> _held = [];
		int _attempts;

		public Rendezvous Rendezvous => rendezvous;

		public int Attempts => Volatile.Read(ref _attempts);

		public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
			CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
		{
			await HoldAsync(command, cancellationToken);
			return result;
		}

		public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
			CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
		{
			await HoldAsync(command, cancellationToken);
			return result;
		}

		async Task HoldAsync(DbCommand command, CancellationToken cancellationToken)
		{
			if (!matches(command.CommandText))
				return;

			Interlocked.Increment(ref _attempts);
			bool first;
			lock (_held)
				first = _held.Add(command.Connection.ShouldNotBeNull());
			if (first)
				await rendezvous.ArriveAsync(cancellationToken);
		}
	}

	/// <summary>
	///     An async barrier: each arrival waits until all <paramref name="participants" /> have arrived, bounded so a
	///     store that never reaches the statement fails the test instead of hanging it.
	/// </summary>
	sealed class Rendezvous(int participants)
	{
		readonly TaskCompletionSource _all = new(TaskCreationOptions.RunContinuationsAsynchronously);
		int _arrived;

		public int Arrived => Volatile.Read(ref _arrived);

		public Task ArriveAsync(CancellationToken cancellationToken)
		{
			if (Interlocked.Increment(ref _arrived) == participants)
				_all.SetResult();
			return _all.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);
		}
	}

	/// <summary>
	///     Before every recovery-code swap, rewrites the set from another connection with the same codes under fresh
	///     ciphertext, so the swap's as-read guard never matches.
	/// </summary>
	sealed class RecoveryCodeSaboteur(IdentityFixture fixture, Guid userId, string codes) : DbCommandInterceptor
	{
		public int Fired { get; private set; }

		public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
			CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
		{
			if (!IsTokenUpdate(command.CommandText))
				return result;

			Fired++;
			await using var other = fixture.CreateContext();
			using (SubjectCryptoScope.Begin(userId))
				await other.UserTokens
					.Where(t => t.UserId == userId && t.LoginProvider == RecoveryCodeProvider && t.Name == RecoveryCodeName)
					.ExecuteUpdateAsync(setters => setters.SetProperty(static t => t.Value, codes), cancellationToken);
			return result;
		}
	}

	/// <summary>How many superseded versions of one user row the history holds.</summary>
	protected abstract Task<long> UserVersionsAsync(NorseIdentityDbContext context, Guid userId);

	/// <summary>Seeds a user with <see cref="Password" /> through the real manager.</summary>
	async Task<NorseUser> SeedWithPasswordAsync(string email)
	{
		NorseUser user = new() { UserName = email, Email = email };
		(await _fixture.CreateUserManager().CreateAsync(user, Password)).Succeeded.ShouldBeTrue();
		return user;
	}

	/// <summary>Two new roles, uniquely named, created through the real role manager.</summary>
	async Task<(string First, string Second)> SeedRolesAsync()
	{
		var roleManager = _fixture.CreateRoleManager();
		string[] names = [$"role-{Guid.NewGuid():N}", $"role-{Guid.NewGuid():N}"];
		foreach (var name in names)
			(await roleManager.CreateAsync(new() { Name = name })).Succeeded.ShouldBeTrue();
		return (names[0], names[1]);
	}

	/// <summary>Whether <paramref name="sql" /> is the credentials statement, whichever provider spells it.</summary>
	static bool IsCredentialsUpdate(string sql) =>
		sql.StartsWith("UPDATE", StringComparison.OrdinalIgnoreCase) &&
		(sql.Contains("user_credentials", StringComparison.Ordinal) || sql.Contains("[UserCredentials]", StringComparison.Ordinal));

	/// <summary>A fresh read of the user through a new scope's store.</summary>
	async Task<NorseUser> RereadAsync(Guid userId) =>
		(await _fixture.CreateUserStore().FindByIdAsync(userId.ToString(), Cancellation)).ShouldNotBeNull();

	/// <summary>
	///     A real <see cref="NorseUserManager" /> over a <see cref="NorseUserStore" /> whose context records every command, so a test
	///     can see which statements the flush issued.
	/// </summary>
	(NorseUserManager Manager, CommandRecorder Commands) RecordingManager()
	{
		CommandRecorder commands = new();
		var context = _fixture.CreateContext(commands);
		_contexts.Add(context);
		return (_fixture.CreateUserManager(new NorseUserStore(context, new())), commands);
	}

	/// <summary>The raw, undecrypted value of one <c>users</c> column, as stored.</summary>
	static Task<string> RawUsersColumnAsync(NorseIdentityDbContext context, string propertyName, Guid userId)
	{
		var (principal, _) = Tables(context);
		var sql = context.GetService<ISqlGenerationHelper>();
		var users = context.Users.EntityType;
		var column = users.GetProperty(propertyName).GetColumnName(principal).ShouldNotBeNull();
		var idColumn = users.GetProperty(nameof(NorseUser.Id)).GetColumnName(principal).ShouldNotBeNull();
		var select =
			$"SELECT {sql.DelimitIdentifier(column)} AS {sql.DelimitIdentifier("Value")} FROM {Delimited(context, principal)} WHERE {sql.DelimitIdentifier(idColumn)} = {{0}}";
		return context.Database
			.SqlQueryRaw<string>(select, userId)
			.SingleAsync(Cancellation);
	}

	/// <summary>The principal table and the <c>user_credentials</c> fragment, as the model maps them.</summary>
	static (StoreObjectIdentifier Principal, StoreObjectIdentifier Fragment) Tables(NorseIdentityDbContext context)
	{
		var users = context.Users.EntityType;
		return (StoreObjectIdentifier.Table(users.GetTableName().ShouldNotBeNull(), users.GetSchema()),
			users.GetMappingFragments().Single().StoreObject);
	}

	static string Delimited(NorseIdentityDbContext context, StoreObjectIdentifier table) =>
		context.GetService<ISqlGenerationHelper>().DelimitIdentifier(table.Name, table.Schema);

	/// <summary>How many rows of <paramref name="table" /> carry the user's id.</summary>
	static Task<int> RowCountAsync(NorseIdentityDbContext context, StoreObjectIdentifier table, Guid userId)
	{
		var sql = context.GetService<ISqlGenerationHelper>();
		var idColumn = context.Users.EntityType.GetProperty(nameof(NorseUser.Id)).GetColumnName(table).ShouldNotBeNull();
		var select =
			$"SELECT COUNT(*) AS {sql.DelimitIdentifier("Value")} FROM {Delimited(context, table)} WHERE {sql.DelimitIdentifier(idColumn)} = {{0}}";
		return context.Database
			.SqlQueryRaw<int>(select, userId)
			.SingleAsync(Cancellation);
	}

	/// <summary>Refuses every user, as a validator a host adds might.</summary>
	sealed class RefusingUserValidator : IUserValidator<NorseUser>
	{
		public const string Code = "Refused";

		public Task<IdentityResult> ValidateAsync(UserManager<NorseUser> manager, NorseUser user) =>
			Task.FromResult(IdentityResult.Failed(new IdentityError { Code = Code, Description = "Refused by the test." }));
	}

	/// <summary>
	///     A token provider whose token verifies exactly once: the second check fails, as a token expiring between two
	///     checks would.
	/// </summary>
	sealed class OnceValidTokenProvider : IUserTwoFactorTokenProvider<NorseUser>
	{
		int _validations;

		public Task<string> GenerateAsync(string purpose, UserManager<NorseUser> manager, NorseUser user) =>
			Task.FromResult("token");

		public Task<bool> ValidateAsync(string purpose, string token, UserManager<NorseUser> manager, NorseUser user) =>
			Task.FromResult(Interlocked.Increment(ref _validations) is 1);

		public Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<NorseUser> manager, NorseUser user) =>
			Task.FromResult(false);
	}

	/// <summary>Every transaction a context begins, and how many it commits.</summary>
	sealed class TransactionRecorder : DbTransactionInterceptor
	{
		public List<DbTransaction> Started { get; } = [];

		public int Committed { get; private set; }

		public override ValueTask<DbTransaction> TransactionStartedAsync(DbConnection connection,
			TransactionEndEventData eventData, DbTransaction result, CancellationToken cancellationToken = default)
		{
			Started.Add(result);
			return ValueTask.FromResult(result);
		}

		public override Task TransactionCommittedAsync(DbTransaction transaction, TransactionEndEventData eventData,
			CancellationToken cancellationToken = default)
		{
			Committed++;
			return Task.CompletedTask;
		}
	}

	/// <summary>Every command a context executes, with the transaction it ran in.</summary>
	sealed class CommandRecorder : DbCommandInterceptor
	{
		public List<(string Sql, DbTransaction? Transaction)> Executed { get; } = [];

		public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
			CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
		{
			Executed.Add((command.CommandText, command.Transaction));
			return ValueTask.FromResult(result);
		}

		public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
			CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
		{
			Executed.Add((command.CommandText, command.Transaction));
			return ValueTask.FromResult(result);
		}
	}
}
