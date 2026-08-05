using Microsoft.EntityFrameworkCore;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

public sealed class ErasureServiceTests(PostgresIdentityFixture fixture) : IClassFixture<PostgresIdentityFixture>
{
	// Decorator: GetAsync/GetOrCreateAsync delegate; the first DestroyAsync throws to simulate a
	// vault outage, every subsequent call (including the retry) delegates normally.
	sealed class ThrowOnceKeyStore(ISubjectKeyStore inner) : ISubjectKeyStore
	{
		bool _thrown;

		public ValueTask<SubjectKeyResult> GetAsync(Guid subjectId, CancellationToken cancellationToken = default) =>
			inner.GetAsync(subjectId, cancellationToken);

		public ValueTask<byte[]> GetOrCreateAsync(Guid subjectId, CancellationToken cancellationToken = default) =>
			inner.GetOrCreateAsync(subjectId, cancellationToken);

		public ValueTask<ErasureReceipt> DestroyAsync(Guid subjectId, CancellationToken cancellationToken = default)
		{
			if (!_thrown)
			{
				_thrown = true;
				throw new InvalidOperationException("simulated vault outage");
			}
			return inner.DestroyAsync(subjectId, cancellationToken);
		}
	}

	[Fact]
	async Task Shred_nulls_lookup_hashes_rotates_the_stamp_and_destroys_the_key()
	{
		var (context, keyStore) = await fixture.CreateScopeAsync();
		var user = await fixture.SeedUserAsync("shred-me@example.com");
		var stampBefore = user.SecurityStamp;

		ErasureService service = new(context, keyStore);
		var outcome = await service.ShredAsync(user.Id, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<ErasureReceipt> success).ShouldBeTrue();
		_ = success;
		// Projected, deliberately not the full entity: Email/UserName are still ciphertext on this
		// row (payload columns darken on erasure, they don't null) and the key is now destroyed, so
		// materializing them here would throw KeyDestroyedException at the value converter -- exactly
		// the "half-severed read" collision discovered while writing this suite (see the revalidation
		// test below). Reading only the three columns this assertion actually needs never touches
		// NorsePersonalDataProtector at all.
		var reloaded = await context.Users.AsNoTracking()
			.Where(u => u.Id == user.Id)
			.Select(u => new { u.NormalizedUserName, u.NormalizedEmail, u.SecurityStamp })
			.SingleAsync(TestContext.Current.CancellationToken);
		reloaded.NormalizedUserName.ShouldBeNull();
		reloaded.NormalizedEmail.ShouldBeNull();
		reloaded.SecurityStamp.ShouldNotBe(stampBefore); // spec §8 verify item 10's trigger
		var keyResult = await keyStore.GetAsync(user.Id, TestContext.Current.CancellationToken);
		keyResult.Match(_ => "available", _ => "destroyed", () => "missing").ShouldBe("destroyed");
	}

	[Fact]
	async Task Session_authenticated_before_shred_dies_at_the_next_revalidation()
	{
		// Verify item 10, closed through the REAL validator path: the pre-shred principal is built by
		// the real NorseUserClaimsPrincipalFactory (so this test also interlocks with Task 17 -- if
		// the allowlist ever drops or renames the stamp claim, the dead-session mechanism breaks HERE,
		// not silently in production), and the post-shred verdict comes from
		// SignInManager.ValidateSecurityStampAsync -- the exact comparison cookie revalidation runs.
		var (context, keyStore) = await fixture.CreateScopeAsync();
		var user = await fixture.SeedUserAsync("session@example.com");
		var signInManager = fixture.CreateSignInManager();
		var principal = await signInManager.CreateUserPrincipalAsync(user); // "the cookie" as issued pre-shred

		(await signInManager.ValidateSecurityStampAsync(principal)).ShouldNotBeNull(); // sanity arm: live before shred

		await new ErasureService(context, keyStore).ShredAsync(user.Id, TestContext.Current.CancellationToken);

		// DISCOVERED GAP (Task 18 review -- Task 19b's fold depends on knowing): revalidation does
		// not die with a clean null verdict here. SignInManager.ValidateSecurityStampAsync calls
		// UserManager.GetUserAsync -> NorseUserStore.FindByIdAsync, which re-materializes the row by
		// id (rows are never deleted, only hashes nulled + the stamp rotated) -- including
		// Email/UserName, both still wired through NorsePersonalDataProtector's EF value converter.
		// Act 3 already destroyed the key, so materializing those columns throws
		// KeyDestroyedException, UNWRAPPED by EF (it propagates straight out of the async
		// enumerator, confirmed via the stack trace at materialization) -- SignInManager has no
		// try/catch around GetUserAsync, so the exception reaches this call site directly instead of
		// the null the ceremony's narrative implied. The session is still provably dead -- this
		// exception IS the kill -- just not via the null-return contract; a future revalidation-path
		// fold (Task 19b) is the right place to translate KeyDestroyedException into "invalid
		// session" at this boundary, not ErasureService.
		await Should.ThrowAsync<KeyDestroyedException>(
			async () => await signInManager.ValidateSecurityStampAsync(principal));
	}

	[Fact]
	async Task Destruction_failure_leaves_a_retryable_half_severed_state_and_a_rerun_completes()
	{
		// The ceremony's partial-failure contract: acts 1-2 committed, act 3 threw -> the subject is
		// half-severed (unfindable, unsigninable, still decryptable, no receipt). Legal because
		// retryable: the re-run matches the row again, re-rotates harmlessly, and completes the
		// destruction. The retry obligation is the future DSAR machinery's contract.
		var (context, keyStore) = await fixture.CreateScopeAsync();
		var user = await fixture.SeedUserAsync("flaky@example.com");
		ThrowOnceKeyStore flaky = new(keyStore); // decorator: first DestroyAsync throws, rest delegate
		ErasureService service = new(context, flaky);

		await Should.ThrowAsync<InvalidOperationException>(
			async () => await service.ShredAsync(user.Id, TestContext.Current.CancellationToken)); // fault propagates -- no swallow

		var half = await context.Users.AsNoTracking().SingleAsync(u => u.Id == user.Id, TestContext.Current.CancellationToken);
		half.NormalizedUserName.ShouldBeNull(); // acts 1-2 committed
		(await keyStore.GetAsync(user.Id, TestContext.Current.CancellationToken))
			.Match(_ => "available", _ => "destroyed", () => "missing").ShouldBe("available"); // key intact, no receipt

		var retry = await service.ShredAsync(user.Id, TestContext.Current.CancellationToken);
		retry.TryGetValue(out Success<ErasureReceipt> receipt).ShouldBeTrue(); // re-run completes with the receipt
		_ = receipt;
	}

	[Fact]
	async Task Shred_of_an_unknown_subject_is_not_found_and_burns_no_key()
	{
		var (context, keyStore) = await fixture.CreateScopeAsync();
		var ghost = Guid.NewGuid();
		var outcome = await new ErasureService(context, keyStore).ShredAsync(ghost, TestContext.Current.CancellationToken);
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.NotFound);
		(await keyStore.GetAsync(ghost, TestContext.Current.CancellationToken))
			.Match(_ => "available", _ => "destroyed", () => "missing").ShouldBe("missing");
	}

	[Fact]
	async Task Reregistration_with_the_same_email_succeeds_because_the_hashes_were_nulled()
	{
		// Spec §4.2: re-registration works via nulling, not key movement -- same HMAC, fresh row.
		var (context, keyStore) = await fixture.CreateScopeAsync();
		var first = await fixture.SeedUserAsync("round-two@example.com");
		await new ErasureService(context, keyStore).ShredAsync(first.Id, TestContext.Current.CancellationToken);
		var second = await fixture.SeedUserAsync("round-two@example.com"); // same email, same blind index value
		second.Id.ShouldNotBe(first.Id);
		var live = await context.Users.AsNoTracking()
			.CountAsync(u => u.NormalizedUserName != null && u.NormalizedUserName == second.NormalizedUserName, TestContext.Current.CancellationToken);
		live.ShouldBe(1); // exactly one live row answers the lookup
	}
}
