using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     Erasure as a hard delete, key first (2026-10-24 explicit-writes spec §7), once per provider: every run that
///     returns <c>Ok</c> did every step, every failure point of §7.3 leaves a state a retry finishes, and concurrent
///     runs return the one authoritative receipt (§7.5).
/// </summary>
/// <remarks>
///     <para>
///         Failures are injected at the two edges erasure owns, never inside Midgard: a decorating
///         <see cref="FaultingSubjectKeyStore" /> over the fixture's real key store, and EF interceptors on a context
///         built from the fixture's own options (<see cref="IdentityFixture.CreateContext" />). States no public call
///         reaches (a pending receipt, a key gone with no receipt) are staged in the development store's documented
///         on-disk shape under <see cref="IdentityFixture.KeysRoot" />. Every table and column name comes from the
///         model, so one body serves both providers' naming conventions.
///     </para>
///     <para>
///         Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///         records: xUnit discovers them on each <see langword="sealed" /> provider class.
///     </para>
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class ErasureServiceSuite(IdentityFixture fixture)
{
	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Shred_deletes_the_row_and_every_child_row_and_destroys_the_key()
	{
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("shred-me@example.com");
		var userManager = fixture.CreateUserManager();
		var reloaded = (await userManager.FindByIdAsync(user.Id.ToString())).ShouldNotBeNull();
		(await userManager.AddClaimAsync(reloaded, new("erasure-test", "claimed"))).Succeeded.ShouldBeTrue();
		var (context, keyStore) = await fixture.CreateScopeAsync();
		(await SplitRowsAsync(context, user.Id)).ShouldBe(1, "the split row exists before the shred");

		var receipt = Receipt(await NewService(context, keyStore).ShredAsync(user.Id, Cancellation));

		(await RowExistsAsync(context, user.Id)).ShouldBeFalse();
		(await SplitRowsAsync(context, user.Id)).ShouldBe(0, "the cascade reaches the split table");
		(await context.Set<NorseUserClaim>().CountAsync(c => c.UserId == user.Id, Cancellation)).ShouldBe(0);
		(await StoredReceiptAsync(keyStore, user.Id)).ShouldBe(receipt);
	}

	// 2026-10-29 OpenIddict spec §5.5: the transaction deletes the subject's OpenIddict sessions too, whether a session
	// names the subject or reaches it only through one of its authorizations, and every token under them, before the
	// authorizations (the sessions' foreign key, no cascade); another subject's session and token are untouched.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_erased_subjects_sessions_are_gone()
	{
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("erase-sessions@example.com");
		var (context, keyStore) = await fixture.CreateScopeAsync();
		var subject = user.Id.ToString();
		var other = Guid.NewGuid().ToString();
		NorseOpenIddictAuthorization authorization = new()
		{
			Id = Guid.CreateVersion7(),
			Subject = subject,
			Status = "valid",
			Type = "permanent",
			CreationDate = DateTime.UtcNow
		};
		NorseOpenIddictSession named = new() { Id = Guid.CreateVersion7(), Subject = subject, AuthorizationId = authorization.Id, Status = "valid" },
			bound = new() { Id = Guid.CreateVersion7(), AuthorizationId = authorization.Id, Status = "valid" },
			unbound = new() { Id = Guid.CreateVersion7(), Subject = subject, Status = "valid" },
			kept = new() { Id = Guid.CreateVersion7(), Subject = other, Status = "valid" };
		NorseOpenIddictToken underSession = new() { Id = Guid.CreateVersion7(), SessionId = unbound.Id, Status = "valid", Type = "refresh_token" },
			keptToken = new() { Id = Guid.CreateVersion7(), Subject = other, SessionId = kept.Id, Status = "valid", Type = "refresh_token" },
			bare = new() { Id = Guid.CreateVersion7(), Subject = subject, Status = "valid", Type = "access_token" };
		context.AddRange(authorization, named, bound, unbound, kept, underSession, keptToken, bare);
		await context.SaveChangesAsync(Cancellation);

		Receipt(await NewService(context, keyStore).ShredAsync(user.Id, Cancellation));

		Guid[] sessions = [named.Id, bound.Id, unbound.Id, kept.Id], tokens = [underSession.Id, keptToken.Id];
		(await context.Set<NorseOpenIddictSession>().Where(s => sessions.Contains(s.Id)).Select(static s => s.Id)
			.ToListAsync(Cancellation)).ShouldBe([kept.Id]);
		(await context.Set<NorseOpenIddictToken>().Where(t => tokens.Contains(t.Id)).Select(static t => t.Id)
			.ToListAsync(Cancellation)).ShouldBe([keptToken.Id]);
		(await context.Set<NorseOpenIddictAuthorization>().AnyAsync(a => a.Id == authorization.Id, Cancellation)).ShouldBeFalse();
		// By subject, not by seeded id: nothing that names the subject survives, a token linked to nothing included.
		(await OpenIddictRowsAsync(context, user.Id)).ShouldBe(0);
		(await context.Set<NorseOpenIddictSession>().CountAsync(s => s.Subject == subject, Cancellation)).ShouldBe(0);
		(await RowExistsAsync(context, user.Id)).ShouldBeFalse();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Session_authenticated_before_shred_dies_at_the_next_revalidation()
	{
		// The real validator path: the pre-shred principal comes from the real claims factory, and the verdict
		// from SignInManager.ValidateSecurityStampAsync, the comparison cookie revalidation runs. The row is gone,
		// so the user is not found and the session dies within one revalidation interval (spec §5).
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("session@example.com");
		var signInManager = fixture.CreateSignInManager();
		var principal = await signInManager.CreateUserPrincipalAsync(user);
		principal.FindFirstValue(new IdentityOptions().ClaimsIdentity.SecurityStampClaimType).ShouldNotBeNull();
		(await signInManager.ValidateSecurityStampAsync(principal)).ShouldNotBeNull(); // live before the shred
		var (context, keyStore) = await fixture.CreateScopeAsync();

		Receipt(await NewService(context, keyStore).ShredAsync(user.Id, Cancellation));

		(await signInManager.ValidateSecurityStampAsync(principal)).ShouldBeNull();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Real_SecurityStampValidator_rejects_the_cookie_without_a_500()
	{
		// The framework path (spec §4.12, §10 Erasure), never .Outcome: the cookie middleware's own
		// SecurityStampValidator<NorseUser>, over a real CookieValidatePrincipalContext, in the key-destroyed window.
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("stamp-window@example.com");
		var principal = await fixture.CreateSignInManager().CreateUserPrincipalAsync(user);
		await OpenKeyDestroyedWindowAsync(user.Id);
		using var scope = fixture.CreateOwnedScope();
		DefaultHttpContext http = new() { RequestServices = scope.ServiceProvider };
		// The validator signs a rejected principal out through its SignInManager, on this request.
		scope.ServiceProvider.GetRequiredService<SignInManager<NorseUser>>().Context = http;
		var validator = scope.ServiceProvider.GetRequiredService<ISecurityStampValidator>();
		validator.ShouldBeOfType<SecurityStampValidator<NorseUser>>();
		AuthenticationScheme scheme = new(IdentityConstants.ApplicationScheme, null, typeof(CookieAuthenticationHandler));
		// Issued a day ago, past the validation interval, so the validator actually checks the stamp.
		AuthenticationProperties properties = new() { IssuedUtc = DateTimeOffset.UtcNow.AddDays(-1) };
		CookieValidatePrincipalContext cookie = new(http, scheme, new CookieAuthenticationOptions(),
			new AuthenticationTicket(principal, properties, scheme.Name));

		await validator.ValidateAsync(cookie); // an escaping exception is the 500

		cookie.Principal.ShouldBeNull("the cookie's principal is rejected");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Real_revalidating_provider_reports_invalid()
	{
		// The framework path: Blazor's revalidation loop calls the provider's own protected entry point, which is
		// what this invokes; .Outcome is never involved.
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("revalidate-window@example.com");
		var principal = await fixture.CreateSignInManager().CreateUserPrincipalAsync(user);
		await OpenKeyDestroyedWindowAsync(user.Id);
		using var scope = fixture.CreateOwnedScope();
		using IdentityRevalidatingAuthenticationStateProvider provider = new(NullLoggerFactory.Instance,
			scope.ServiceProvider.GetRequiredService<IServiceScopeFactory>(),
			scope.ServiceProvider.GetRequiredService<IOptions<IdentityOptions>>());
		var entry = typeof(IdentityRevalidatingAuthenticationStateProvider).GetMethod("ValidateAuthenticationStateAsync",
			BindingFlags.NonPublic | BindingFlags.Instance).ShouldNotBeNull();

		var valid = await (Task<bool>)entry.Invoke(provider, [new AuthenticationState(principal), Cancellation])!;

		valid.ShouldBeFalse();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Real_password_sign_in_in_the_key_destroyed_window_fails_closed()
	{
		// Spec §5: a login in the window is a failed sign-in through LoginHandler's single static Failed. The real
		// NorseSignInManager lets the store's KeyDestroyedException cross its plumbing (spec §4.12: the managers stay
		// stock, and only the two framework-driven boundaries fold it), so the Norse login path classifies it at the
		// .Outcome view, which answers Erased as an outcome, and LoginHandler collapses that onto its one instance.
		fixture.SkipUnlessAvailable();
		const string Email = "login-window@example.com";
		const string Password = "Correct-Horse-1!";
		NorseUser user = new() { UserName = Email, Email = Email };
		(await fixture.CreateUserManager().CreateAsync(user, Password)).Succeeded.ShouldBeTrue();
		await OpenKeyDestroyedWindowAsync(user.Id);
		using var scope = fixture.CreateOwnedScope();
		var signInManager = scope.ServiceProvider.GetRequiredService<SignInManager<NorseUser>>();
		signInManager.ShouldBeOfType<NorseSignInManager>();
		var handler = scope.ServiceProvider.GetRequiredService<IRequestHandler<LoginCommand, NavigationResult>>();
		handler.ShouldBeOfType<LoginHandler>();
		// A login always runs on a request: the handler resolves its landing against the request's PathBase.
		scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>().HttpContext = new DefaultHttpContext();
		// The anti-enumeration reference: an unknown email through the same real handler.
		var unknown = await handler.Handle(new(new LoginRequest { EmailInput = "no-such-user@example.com", Password = Password }),
			Cancellation);

		var viewed = await signInManager.Outcome.PasswordSignInAsync(Email, Password, isPersistent: false,
			lockoutOnFailure: true, Cancellation);
		var login = await handler.Handle(new(new LoginRequest { EmailInput = Email, Password = Password }), Cancellation);

		viewed.TryGetValue(out Failed erased).ShouldBeTrue("an outcome, never an exception");
		erased.Problem.Category.ShouldBe(ErrorCategory.Erased);
		unknown.TryGetValue(out Failed expected).ShouldBeTrue();
		login.TryGetValue(out Failed failed).ShouldBeTrue("the correct password in the window still fails");
		failed.Problem.ShouldBeSameAs(expected.Problem, "an erased account reads exactly as bad credentials");
		(await RowExistsAsync((await fixture.CreateScopeAsync()).Context, user.Id)).ShouldBeTrue("still the window");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Failure_during_destroy_then_retry_completes()
	{
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("fail-during-destroy@example.com");
		var (context, keyStore) = await fixture.CreateScopeAsync();
		FaultingSubjectKeyStore faulting = new(keyStore) { FailBeforeDestroy = new IOException("simulated outage") };
		var service = NewService(context, faulting);

		ShouldBeFault(await service.ShredAsync(user.Id, Cancellation));
		(await KeyStateAsync(keyStore, user.Id)).ShouldBe("available");
		(await RowExistsAsync(context, user.Id)).ShouldBeTrue();

		var receipt = Receipt(await service.ShredAsync(user.Id, Cancellation));
		(await StoredReceiptAsync(keyStore, user.Id)).ShouldBe(receipt);
		(await RowExistsAsync(context, user.Id)).ShouldBeFalse();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Failure_after_destroy_before_transaction_then_retry_completes()
	{
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("fail-after-destroy@example.com");
		var (context, keyStore) = await fixture.CreateScopeAsync();
		FaultingSubjectKeyStore faulting = new(keyStore) { FailAfterDestroy = new IOException("simulated lost answer") };
		var service = NewService(context, faulting);

		ShouldBeFault(await service.ShredAsync(user.Id, Cancellation));
		// The §5 window: the key is gone, the rows are intact.
		var stored = await StoredReceiptAsync(keyStore, user.Id);
		(await RowExistsAsync(context, user.Id)).ShouldBeTrue();

		Receipt(await service.ShredAsync(user.Id, Cancellation)).ShouldBe(stored);
		(await RowExistsAsync(context, user.Id)).ShouldBeFalse();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Retrying_shred_finishes_a_failure_after_destroy_within_one_call()
	{
		// PR #76 review: past the key's destruction the caller can no longer materialize the account, nor keep its
		// session, so an interactive caller's retry has to happen inside the request that destroyed the key.
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("retry-after-destroy@example.com");
		var (context, keyStore) = await fixture.CreateScopeAsync();
		FaultingSubjectKeyStore faulting = new(keyStore) { FailAfterDestroy = new IOException("simulated lost answer") };

		var receipt = Receipt(await NewService(context, faulting).ShredWithRetriesAsync(user.Id, 3, Cancellation));

		receipt.ShouldBe(await StoredReceiptAsync(keyStore, user.Id));
		faulting.DestroyCalls.ShouldBe(2, "one failed run, then the retry that finished it");
		(await RowExistsAsync(context, user.Id)).ShouldBeFalse();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Retrying_shred_gives_up_after_its_attempts_with_the_last_outcome()
	{
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("retry-exhausted@example.com");
		var (context, keyStore) = await fixture.CreateScopeAsync();
		FaultingSubjectKeyStore faulting = new(keyStore) { FailEveryDestroy = new IOException("simulated outage") };

		ShouldBeFault(await NewService(context, faulting).ShredWithRetriesAsync(user.Id, 3, Cancellation));

		faulting.DestroyCalls.ShouldBe(3);
		(await RowExistsAsync(context, user.Id)).ShouldBeTrue("the rows wait behind the destroyed key for an operator");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Retrying_shred_does_not_retry_NotFound()
	{
		fixture.SkipUnlessAvailable();
		var (context, keyStore) = await fixture.CreateScopeAsync();
		FaultingSubjectKeyStore faulting = new(keyStore);

		ShouldBe(await NewService(context, faulting).ShredWithRetriesAsync(Guid.NewGuid(), 3, Cancellation), ErrorCategory.NotFound);

		faulting.DestroyCalls.ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Failure_after_commit_then_retry_returns_same_receipt()
	{
		// The commit landed and its acknowledgement was lost: Indeterminate, never Fault, which would claim no effect
		// (spec §4.12; flipped from Fault in Task 4.9, which gave erasure the commit-outcome contract).
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("fail-after-commit@example.com");
		var (_, keyStore) = await fixture.CreateScopeAsync();
		CommitFailureInterceptor interceptor = new(CommitFailure.AfterCommit);
		await using var context = fixture.CreateContext(interceptor);
		var service = NewService(context, keyStore);

		ShouldBe(await service.ShredAsync(user.Id, Cancellation), ErrorCategory.Indeterminate);
		interceptor.Fired.ShouldBe(1);
		(await RowExistsAsync(context, user.Id)).ShouldBeFalse("the transaction committed before the failure");
		var stored = await StoredReceiptAsync(keyStore, user.Id);

		Receipt(await service.ShredAsync(user.Id, Cancellation)).ShouldBe(stored);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Erasure_failure_before_commit_is_definite_and_database_unchanged()
	{
		// The §5 window: the key is destroyed, the transaction rolled back, and the outcome is an honest Fault.
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("erasure-before-commit@example.com");
		var (seedContext, keyStore) = await fixture.CreateScopeAsync();
		await SeedOpenIddictRowsAsync(seedContext, user.Id);
		CommitFailureInterceptor interceptor = new(CommitFailure.BeforeCommit);
		await using var context = fixture.CreateContext(interceptor);

		ShouldBe(await NewService(context, keyStore).ShredAsync(user.Id, Cancellation), ErrorCategory.Fault);

		interceptor.Fired.ShouldBe(1);
		interceptor.Commits.ShouldBe(1, "nothing replays the transaction");
		(await RowExistsAsync(seedContext, user.Id)).ShouldBeTrue();
		(await SplitRowsAsync(seedContext, user.Id)).ShouldBe(1);
		(await OpenIddictRowsAsync(seedContext, user.Id)).ShouldBe(2);
		await StoredReceiptAsync(keyStore, user.Id);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Erasure_ack_loss_without_marker_returns_Indeterminate()
	{
		// No stamp marker exists for erasure: the outcome stays Indeterminate even though every row is in fact gone.
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("erasure-ack-loss@example.com");
		var (seedContext, keyStore) = await fixture.CreateScopeAsync();
		await SeedOpenIddictRowsAsync(seedContext, user.Id);
		CommitFailureInterceptor interceptor = new(CommitFailure.AfterCommit);
		await using var context = fixture.CreateContext(interceptor);

		ShouldBe(await NewService(context, keyStore).ShredAsync(user.Id, Cancellation), ErrorCategory.Indeterminate);

		interceptor.Fired.ShouldBe(1);
		interceptor.Commits.ShouldBe(1, "nothing replays the transaction");
		(await RowExistsAsync(seedContext, user.Id)).ShouldBeFalse("the commit landed");
		(await OpenIddictRowsAsync(seedContext, user.Id)).ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Erasure_indeterminate_commit_then_retry_completes()
	{
		// Spec §7.3: an indeterminate commit is safe to re-run either way, and retry-until-Ok is the caller's obligation.
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("erasure-indeterminate-retry@example.com");
		var (seedContext, keyStore) = await fixture.CreateScopeAsync();
		await SeedOpenIddictRowsAsync(seedContext, user.Id);
		CommitFailureInterceptor interceptor = new(CommitFailure.AfterCommit);
		await using var context = fixture.CreateContext(interceptor);
		var service = NewService(context, keyStore);
		ShouldBe(await service.ShredAsync(user.Id, Cancellation), ErrorCategory.Indeterminate);
		interceptor.Fired.ShouldBe(1);

		var receipt = Receipt(await service.ShredAsync(user.Id, Cancellation));

		interceptor.Commits.ShouldBe(2, "the caller's retry, and nothing else, ran the transaction again");
		receipt.ShouldBe(await StoredReceiptAsync(keyStore, user.Id));
		(await RowExistsAsync(seedContext, user.Id)).ShouldBeFalse();
		(await SplitRowsAsync(seedContext, user.Id)).ShouldBe(0);
		(await OpenIddictRowsAsync(seedContext, user.Id)).ShouldBe(0);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Absent_row_live_key_leftover_OpenIddict_rows_cleanup_failure_then_retry_cleans_up()
	{
		// r2's hole (spec §7.3, last row): the row went earlier, the OpenIddict cleanup never ran, and the key is
		// still live. A run whose cleanup fails is not success; the retry deletes the leftovers.
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("leftover-openiddict@example.com");
		var (seedContext, keyStore) = await fixture.CreateScopeAsync();
		await SeedOpenIddictRowsAsync(seedContext, user.Id);
		await DeleteUserRowAsync(seedContext, user.Id);
		(await KeyStateAsync(keyStore, user.Id)).ShouldBe("available");
		await using var context = fixture.CreateContext(new FailingCommandInterceptor(DelimitedTable<NorseOpenIddictToken>(seedContext)));
		var service = NewService(context, keyStore);

		ShouldBeFault(await service.ShredAsync(user.Id, Cancellation));
		(await OpenIddictRowsAsync(seedContext, user.Id)).ShouldBe(2, "the failed transaction deleted nothing");

		var receipt = Receipt(await service.ShredAsync(user.Id, Cancellation));
		(await OpenIddictRowsAsync(seedContext, user.Id)).ShouldBe(0);
		(await StoredReceiptAsync(keyStore, user.Id)).ShouldBe(receipt);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Pending_receipt_then_retry_promotes_it()
	{
		// Staged as Midgard's KeyDeleted checkpoint leaves it: key file gone, receipt published but not
		// promoted. GetAsync answers Destroyed off the pending file, and the run must still call DestroyAsync,
		// which is the only thing that promotes it.
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("pending-receipt@example.com");
		var (context, keyStore) = await fixture.CreateScopeAsync();
		var pending = await keyStore.DestroyAsync(user.Id, Cancellation);
		var receiptPath = Path.Combine(fixture.KeysRoot, $"{user.Id:N}.receipt");
		var pendingPath = $"{receiptPath}.pending";
		File.Move(receiptPath, pendingPath);
		(await StoredReceiptAsync(keyStore, user.Id)).ShouldBe(pending);

		Receipt(await NewService(context, keyStore).ShredAsync(user.Id, Cancellation)).ShouldBe(pending);

		File.Exists(receiptPath).ShouldBeTrue("the receipt is promoted");
		File.Exists(pendingPath).ShouldBeFalse();
		(await RowExistsAsync(context, user.Id)).ShouldBeFalse();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Missing_key_and_absent_row_is_NotFound_with_no_writes()
	{
		fixture.SkipUnlessAvailable();
		var (context, keyStore) = await fixture.CreateScopeAsync();
		FaultingSubjectKeyStore recording = new(keyStore);
		var ghost = Guid.NewGuid();

		var outcome = await NewService(context, recording).ShredAsync(ghost, Cancellation);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.NotFound);
		recording.DestroyCalls.ShouldBe(0, "no key is burned for a ghost");
		(await KeyStateAsync(keyStore, ghost)).ShouldBe("missing");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Missing_key_with_present_row_is_Fault()
	{
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("missing-key@example.com");
		var (context, keyStore) = await fixture.CreateScopeAsync();
		File.Delete(Path.Combine(fixture.KeysRoot, $"{user.Id:N}.key")); // no key, no receipt: an incident
		(await KeyStateAsync(keyStore, user.Id)).ShouldBe("missing");
		FaultingSubjectKeyStore recording = new(keyStore);

		ShouldBeFault(await NewService(context, recording).ShredAsync(user.Id, Cancellation));

		recording.DestroyCalls.ShouldBe(0);
		(await RowExistsAsync(context, user.Id)).ShouldBeTrue("an incident is not an erasure");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Concurrent_shreds_return_the_same_receipt()
	{
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("concurrent-shred@example.com");
		List<(NorseIdentityDbContext Context, ISubjectKeyStore KeyStore)> scopes = [];
		for (var i = 0; i < 8; i++)
			scopes.Add(await fixture.CreateScopeAsync()); // one context per caller; contexts aren't thread-safe

		var outcomes = await Task.WhenAll(scopes
			.Select(scope => Task.Run(() => NewService(scope.Context, scope.KeyStore).ShredAsync(user.Id, Cancellation),
				Cancellation)));

		var stored = await StoredReceiptAsync(scopes[0].KeyStore, user.Id);
		outcomes
			.Select(Receipt)
			.ShouldAllBe(receipt => receipt == stored);
		(await RowExistsAsync(scopes[0].Context, user.Id)).ShouldBeFalse();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Re_registration_of_erased_email_succeeds()
	{
		fixture.SkipUnlessAvailable();
		var first = await fixture.SeedUserAsync("round-two@example.com");
		var (context, keyStore) = await fixture.CreateScopeAsync();
		Receipt(await NewService(context, keyStore).ShredAsync(first.Id, Cancellation));

		var second = await fixture.SeedUserAsync("round-two@example.com"); // same email, same blind index value

		second.Id.ShouldNotBe(first.Id);
		(await context.Users.CountAsync(u => u.NormalizedUserName == second.NormalizedUserName, Cancellation))
			.ShouldBe(1);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Lock_exhaustion_maps_to_Fault_not_an_exception()
	{
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("lock-exhaustion@example.com");
		var (context, keyStore) = await fixture.CreateScopeAsync();
		// What DevelopmentSubjectKeyStore.DestroyAsync throws when its bounded acquisition runs out.
		FaultingSubjectKeyStore exhausted = new(keyStore) { FailBeforeDestroy = new TimeoutException("lock exhausted") };

		ShouldBeFault(await NewService(context, exhausted).ShredAsync(user.Id, Cancellation));

		(await KeyStateAsync(keyStore, user.Id)).ShouldBe("available");
		(await RowExistsAsync(context, user.Id)).ShouldBeTrue();
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task History_after_erasure_holds_only_ciphertext_and_non_PII_flags()
	{
		// Spec §7.4: what survives a deleted subject in users history is ciphertext under the destroyed key,
		// flags, stamps and our own opaque id. Every column of every version the subject left is scanned, by the
		// catalog's column list rather than the model's, so a column the model has never heard of is scanned too.
		fixture.SkipUnlessAvailable();
		string[] plaintexts =
		[
			"history-erasure@example.com", "+15555550123", "+15555550199", "history-erasure-after@example.com"
		];
		var user = await fixture.SeedUserAsync(plaintexts[0], plaintexts[1]);
		var userManager = fixture.CreateUserManager();
		var reloaded = (await userManager.FindByIdAsync(user.Id.ToString())).ShouldNotBeNull();
		(await userManager.SetPhoneNumberAsync(reloaded, plaintexts[2])).Succeeded.ShouldBeTrue();
		(await userManager.SetEmailAsync(reloaded, plaintexts[3])).Succeeded.ShouldBeTrue();
		var (context, keyStore) = await fixture.CreateScopeAsync();

		Receipt(await NewService(context, keyStore).ShredAsync(user.Id, Cancellation));

		var history = await UsersHistoryAsync(context, user.Id);
		// Two updates each closed a version, and the delete closed the last one.
		history.Rows.Count.ShouldBe(3);
		var protectedColumns = ProtectedPersonalDataColumns(context);
		protectedColumns.ShouldNotBeEmpty();
		protectedColumns.ShouldBeSubsetOf(history.Columns, "every [ProtectedPersonalData] column is versioned and scanned");
		var envelope = $"v1:{user.Id:D}:";
		foreach (var row in history.Rows)
		{
			foreach (var (column, type, value) in row)
			{
				if (protectedColumns.Contains(column))
					(value is null || value is string text && text.StartsWith(envelope, StringComparison.Ordinal))
						.ShouldBeTrue($"{column} holds '{value}', not a v1 envelope under the subject's key");
				else
					IsFlagStampIdOrPeriod(type).ShouldBeTrue(
						$"{column} ({type.Name}) is neither [ProtectedPersonalData] nor a flag, stamp, id or period");
				if (value?.ToString() is { } rendered)
				{
					foreach (var plaintext in plaintexts)
						rendered.ShouldNotContain(plaintext, Case.Insensitive, $"{column} carries a plaintext");
				}
			}
		}
	}

	/// <summary>The physical name of the <c>users</c> history table.</summary>
	protected abstract string UsersHistoryTable { get; }

	/// <summary>The CLR type the provider reads a history period column as.</summary>
	protected abstract Type PeriodType { get; }

	/// <summary>
	///     The non-PII shapes history may keep (spec §7.4): flags (<see cref="bool" />), stamps and ids
	///     (<see cref="Guid" />), and the period. Never a string or bytes -- any text column must be
	///     <c>[ProtectedPersonalData]</c> and so ciphertext.
	/// </summary>
	bool IsFlagStampIdOrPeriod(Type type) =>
		type == typeof(bool) || type == typeof(Guid) || type == PeriodType;

	/// <summary>
	///     The <c>users</c> columns ASP.NET Core Identity encrypts, from the model's <c>[ProtectedPersonalData]</c>
	///     metadata -- the same attribute <c>OnModelCreating</c> keys its protector converters on -- never a hand list.
	/// </summary>
	static HashSet<string> ProtectedPersonalDataColumns(NorseIdentityDbContext context)
	{
		var users = context.Users.EntityType;
		var principal = StoreObjectIdentifier.Table(users.GetTableName().ShouldNotBeNull(), users.GetSchema());
		return users.GetProperties()
			.Where(static property => property.PropertyInfo is { } info &&
				Attribute.IsDefined(info, typeof(ProtectedPersonalDataAttribute), inherit: true))
			.Select(property => property.GetColumnName(principal))
			.OfType<string>()
			.ToHashSet(StringComparer.Ordinal);
	}

	/// <summary>
	///     Every version of one subject in <c>users</c> history, every column as the catalog lists it, read raw so no
	///     value converter can decrypt or reshape anything on the way.
	/// </summary>
	[SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities",
		Justification = "Only catalog and model identifiers, delimited by the provider, reach the text; the subject is a parameter.")]
	async Task<(List<string> Columns, List<List<(string Column, Type Type, object? Value)>> Rows)> UsersHistoryAsync(
		NorseIdentityDbContext context, Guid userId)
	{
		var columns = await context.Database.SqlQuery<string>(
			$"""
			SELECT column_name AS "Value" FROM information_schema.columns
			WHERE table_name = {UsersHistoryTable}
			ORDER BY ordinal_position
			""").ToListAsync(Cancellation);
		columns.ShouldNotBeEmpty();
		var sql = context.GetService<ISqlGenerationHelper>();
		var (_, idColumn) = PrincipalTable(context);
		var select =
			$"SELECT {string.Join(", ", columns.Select(sql.DelimitIdentifier))} FROM {sql.DelimitIdentifier(UsersHistoryTable)} WHERE {idColumn} = @subject";

		await context.Database.OpenConnectionAsync(Cancellation);
		try
		{
			await using var command = context.Database.GetDbConnection().CreateCommand();
			command.CommandText = select;
			var subject = command.CreateParameter();
			subject.ParameterName = "subject";
			subject.Value = userId;
			command.Parameters.Add(subject);
			await using var reader = await command.ExecuteReaderAsync(Cancellation);
			List<List<(string, Type, object?)>> rows = [];
			while (await reader.ReadAsync(Cancellation))
				rows.Add([
					.. Enumerable.Range(0, reader.FieldCount)
						.Select(i => (reader.GetName(i), reader.GetFieldType(i), reader.IsDBNull(i) ? null : reader.GetValue(i)))
				]);
			return (columns, rows);
		}
		finally
		{
			await context.Database.CloseConnectionAsync();
		}
	}

	/// <summary>
	///     The key-destroyed window (spec §5): the key destroyed, the rows intact, as a shred that failed after
	///     destroying leaves them. Proven open: materializing the user throws <see cref="KeyDestroyedException" />.
	/// </summary>
	async Task OpenKeyDestroyedWindowAsync(Guid userId)
	{
		var (context, keyStore) = await fixture.CreateScopeAsync();
		FaultingSubjectKeyStore faulting = new(keyStore) { FailAfterDestroy = new IOException("simulated lost answer") };
		ShouldBeFault(await NewService(context, faulting).ShredAsync(userId, Cancellation));
		(await RowExistsAsync(context, userId)).ShouldBeTrue();
		await Should.ThrowAsync<KeyDestroyedException>(() => fixture.CreateUserManager().FindByIdAsync(userId.ToString()));
	}

	static ErasureService NewService(NorseIdentityDbContext context, ISubjectKeyStore keyStore) =>
		new(context, keyStore, NullLogger<ErasureService>.Instance);

	static ErasureReceipt Receipt(Outcome<ErasureReceipt> outcome) =>
		outcome.Match(static receipt => receipt,
			static problem => throw new ShouldAssertException($"Expected a receipt, got {problem.Category}."));

	static void ShouldBeFault(Outcome<ErasureReceipt> outcome) =>
		ShouldBe(outcome, ErrorCategory.Fault);

	static void ShouldBe(Outcome<ErasureReceipt> outcome, ErrorCategory category)
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(category);
	}

	static async Task<string> KeyStateAsync(ISubjectKeyStore keyStore, Guid subjectId) =>
		(await keyStore.GetAsync(subjectId, Cancellation)).Match(_ => "available", _ => "destroyed", () => "missing");

	static async Task<ErasureReceipt> StoredReceiptAsync(ISubjectKeyStore keyStore, Guid subjectId) =>
		(await keyStore.GetAsync(subjectId, Cancellation)).Match(
			_ => throw new ShouldAssertException("The key is still available."),
			receipt => receipt,
			() => throw new ShouldAssertException("The key is missing."));

	static Task<bool> RowExistsAsync(NorseIdentityDbContext context, Guid userId) =>
		context.Users.AnyAsync(u => u.Id == userId, Cancellation);

	/// <summary>How many OpenIddict tokens and authorizations name the subject.</summary>
	internal static Task<int> OpenIddictRowsAsync(NorseIdentityDbContext context, Guid userId)
	{
		var subject = userId.ToString();
		return context.Set<NorseOpenIddictToken>()
			.Where(t => t.Subject == subject)
			.Select(t => t.Id)
			.Concat(context.Set<NorseOpenIddictAuthorization>()
				.Where(a => a.Subject == subject)
				.Select(a => a.Id))
			.CountAsync(Cancellation);
	}

	/// <summary>Seeds one authorization and one token under it, both naming the subject.</summary>
	internal static async Task SeedOpenIddictRowsAsync(NorseIdentityDbContext context, Guid userId)
	{
		var subject = userId.ToString();
		NorseOpenIddictAuthorization authorization = new()
		{
			Subject = subject,
			Status = "valid",
			Type = "permanent",
			CreationDate = DateTime.UtcNow
		};
		context.AddRange(authorization,
			new NorseOpenIddictToken
			{
				Subject = subject,
				Status = "valid",
				Type = "refresh_token",
				CreationDate = DateTime.UtcNow,
				Authorization = authorization
			});
		await context.SaveChangesAsync(Cancellation);
	}

	/// <summary>The row alone, as an earlier run would have left it: raw, because ExecuteDelete refuses a split entity.</summary>
	static async Task DeleteUserRowAsync(NorseIdentityDbContext context, Guid userId)
	{
		var (table, idColumn) = PrincipalTable(context);
		// Identifiers from the model, delimited by the provider; the id is a parameter.
		var delete = $"DELETE FROM {table} WHERE {idColumn} = {{0}}";
		(await context.Database.ExecuteSqlRawAsync(delete, [userId], Cancellation)).ShouldBe(1);
	}

	/// <summary>The user's row in the split table (<c>user_credentials</c>), read through the model's fragment.</summary>
	static Task<int> SplitRowsAsync(NorseIdentityDbContext context, Guid userId)
	{
		var users = context.Users.EntityType;
		var fragment = users.GetMappingFragments().Single().StoreObject;
		var sql = context.GetService<ISqlGenerationHelper>();
		var idColumn = sql.DelimitIdentifier(users.GetProperty(nameof(NorseUser.Id)).GetColumnName(fragment).ShouldNotBeNull());
		var table = sql.DelimitIdentifier(fragment.Name, fragment.Schema);
		var select = $"SELECT {idColumn} AS {sql.DelimitIdentifier("Value")} FROM {table} WHERE {idColumn} = {{0}}";
		return context.Database
			.SqlQueryRaw<Guid>(select, userId)
			.CountAsync(Cancellation);
	}

	static (string Table, string IdColumn) PrincipalTable(NorseIdentityDbContext context)
	{
		var users = context.Users.EntityType;
		var tableName = users.GetTableName().ShouldNotBeNull();
		var sql = context.GetService<ISqlGenerationHelper>();
		var idColumn = users.GetProperty(nameof(NorseUser.Id))
			.GetColumnName(StoreObjectIdentifier.Table(tableName, users.GetSchema())).ShouldNotBeNull();
		return (sql.DelimitIdentifier(tableName, users.GetSchema()), sql.DelimitIdentifier(idColumn));
	}

	static string DelimitedTable<TEntity>(NorseIdentityDbContext context)
		where TEntity : class
	{
		var entityType = context.Set<TEntity>().EntityType;
		return context.GetService<ISqlGenerationHelper>()
			.DelimitIdentifier(entityType.GetTableName().ShouldNotBeNull(), entityType.GetSchema());
	}
}
