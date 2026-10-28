using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests.Account;

/// <summary>
///     <see cref="DeletePersonalDataHandler" />, the self-service front door to erasure (2026-10-26 account-lifecycle
///     spec §5.6), once per provider. <see cref="ErasureService" /> is sealed over a real context and key store, so
///     every fact runs over the provider's real database: the password check, the shred, and the sign-out it ends with.
/// </summary>
/// <remarks>
///     Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///     records: xUnit discovers them on each <see langword="sealed" /> provider class.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class DeletePersonalDataHandlerSuite(IdentityFixture fixture) : IDisposable
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	/// <summary>The password every user with one starts with.</summary>
	const string Password = "Correct-Horse-1!";

	readonly List<IServiceScope> _scopes = [];

	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Theory(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	[InlineData("wrong")]
	[InlineData("")] // the always-present field, left empty on a password account
	protected async Task A_wrong_password_answers_the_static_instance_and_shreds_nothing(string password)
	{
		fixture.SkipUnlessAvailable();
		var userId = await SeedAsync(withPassword: true);
		DefaultHttpContext http = new();

		var outcome = await HandleAsync(http, await FreshErasureAsync(), userId, password);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		// Failed is a record struct, so the reference identity is its Problem's.
		failed.Problem.ShouldBeSameAs(DeletePersonalDataHandler.IncorrectPassword.Problem);
		(await RereadAsync(userId)).ShouldNotBeNull();
		http.Response.Headers.SetCookie.ShouldBeEmpty("a refused erasure signs nobody out");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_passwordless_account_is_shredded_without_a_password_check()
	{
		fixture.SkipUnlessAvailable();
		var userId = await SeedAsync(withPassword: false);
		DefaultHttpContext http = new();

		var outcome = await HandleAsync(http, await FreshErasureAsync(), userId, "");

		NextUrlOf(outcome).ShouldBe("/");
		(await RereadAsync(userId)).ShouldBeNull();
		http.Response.Headers.SetCookie.ShouldContain(
			static cookie => cookie!.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase),
			"the sign-out expires the cookie");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_password_account_is_shredded_and_signed_out_with_the_right_password()
	{
		fixture.SkipUnlessAvailable();
		var userId = await SeedAsync(withPassword: true);
		DefaultHttpContext http = new();
		var (context, keyStore) = await fixture.CreateScopeAsync();

		var outcome = await HandleAsync(http, NewErasure(context, keyStore), userId, Password);

		NextUrlOf(outcome).ShouldBe("/");
		(await RereadAsync(userId)).ShouldBeNull();
		(await keyStore.GetAsync(userId, Cancellation))
			.Match(static _ => "available", static _ => "destroyed", static () => "missing")
			.ShouldBe("destroyed");
		http.Response.Headers.SetCookie.ShouldContain(
			static cookie => cookie!.Contains("expires=Thu, 01 Jan 1970", StringComparison.OrdinalIgnoreCase),
			"the sign-out expires the cookie");
		var again = await HandleAsync(new(), await FreshErasureAsync(), userId, Password);
		again.TryGetValue(out Failed gone).ShouldBeTrue();
		gone.Problem.Category.ShouldBe(ErrorCategory.NotFound);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_unacknowledged_shred_keeps_Indeterminate_under_the_one_wording()
	{
		// The CommitOutcomeSuite recipe, once per attempt: a CommitFailureInterceptor fails only the first commit it
		// sees, so one per retry keeps every attempt's acknowledgement lost and the last outcome Indeterminate.
		fixture.SkipUnlessAvailable();
		var userId = await SeedAsync(withPassword: true);
		DefaultHttpContext http = new();
		var (_, keyStore) = await fixture.CreateScopeAsync();
		CommitFailureInterceptor[] interceptors =
		[
			.. Enumerable.Range(0, DeletePersonalDataHandler.ShredAttempts).Select(static _ => new CommitFailureInterceptor(CommitFailure.AfterCommit))
		];
		await using var context = fixture.CreateContext(interceptors);

		var outcome = await HandleAsync(http, NewErasure(context, keyStore), userId, Password);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Indeterminate);
		failed.Problem.Errors.Keys.ShouldBe([""]);
		failed.Problem.Errors[""].ShouldBe([DeletePersonalDataHandler.ShredFailureMessage]);
		interceptors.ShouldAllBe(static interceptor => interceptor.Fired == 1);
		(await RereadAsync(userId)).ShouldBeNull("the first attempt's commit landed; only its acknowledgements were lost");
		http.Response.Headers.SetCookie.ShouldBeEmpty("an unconfirmed erasure signs nobody out");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_failed_shred_keeps_Fault_under_the_one_wording_and_leaves_the_row()
	{
		// A definite failure on every attempt: the key is destroyed and the run faults before the deletes, so the
		// rows wait behind the destroyed key for an operator.
		fixture.SkipUnlessAvailable();
		var userId = await SeedAsync(withPassword: true);
		DefaultHttpContext http = new();
		var (context, keyStore) = await fixture.CreateScopeAsync();
		FaultingSubjectKeyStore faulting = new(keyStore) { FailEveryDestroy = new IOException("simulated outage") };

		var outcome = await HandleAsync(http, NewErasure(context, faulting), userId, Password);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Fault);
		failed.Problem.Errors.Keys.ShouldBe([""]);
		failed.Problem.Errors[""].ShouldBe([DeletePersonalDataHandler.ShredFailureMessage]);
		faulting.DestroyCalls.ShouldBe(DeletePersonalDataHandler.ShredAttempts);
		(await RowExistsAsync(userId)).ShouldBeTrue("a failed erasure deletes nothing");
		http.Response.Headers.SetCookie.ShouldBeEmpty("a failed erasure signs nobody out");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_erased_subject_answers_Erased()
	{
		fixture.SkipUnlessAvailable();
		var userId = await SeedAsync(withPassword: true);
		var (context, keyStore) = await fixture.CreateScopeAsync();
		// The key-destroyed window: the key gone, the rows intact, as a shred that failed after destroying leaves them.
		FaultingSubjectKeyStore faulting = new(keyStore) { FailAfterDestroy = new IOException("simulated lost answer") };
		(await NewErasure(context, faulting).ShredAsync(userId, Cancellation)).TryGetValue(out Failed _).ShouldBeTrue();
		DefaultHttpContext http = new();

		var outcome = await HandleAsync(http, await FreshErasureAsync(), userId, Password);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Erased);
		http.Response.Headers.SetCookie.ShouldBeEmpty();
	}

	/// <inheritdoc />
	public void Dispose()
	{
		foreach (var scope in _scopes)
			scope.Dispose();
		GC.SuppressFinalize(this);
	}

	/// <summary>Runs <paramref name="password" /> through a handler built over <paramref name="http" />.</summary>
	ValueTask<Outcome<NavigationResult>> HandleAsync(DefaultHttpContext http, ErasureService erasure, Guid userId,
		string password) =>
		BuildHandler(http, erasure, userId).Handle(new(new() { Password = password }), Cancellation);

	/// <summary>
	///     The handler over real managers, on a request context whose services can sign out, as a page's request has.
	/// </summary>
	DeletePersonalDataHandler BuildHandler(DefaultHttpContext http, ErasureService erasure, Guid userId)
	{
		var scope = fixture.CreateOwnedScope();
		_scopes.Add(scope);
		http.RequestServices = scope.ServiceProvider;
		var userManager = fixture.CreateUserManager();
		var signInManager = fixture.CreateSignInManager(userManager);
		signInManager.Context = http;
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(http);
		return new(userManager, signInManager, FakePrincipal.For(userId), erasure,
			new(Substitute.For<IDeferredSignIn>(), accessor), accessor, NullLogger<DeletePersonalDataHandler>.Instance);
	}

	async Task<ErasureService> FreshErasureAsync()
	{
		var (context, keyStore) = await fixture.CreateScopeAsync();
		return NewErasure(context, keyStore);
	}

	static ErasureService NewErasure(NorseIdentityDbContext context, ISubjectKeyStore keyStore) =>
		new(context, keyStore, NullLogger<ErasureService>.Instance);

	/// <summary>A new user, created through the real manager, with or without <see cref="Password" />.</summary>
	async Task<Guid> SeedAsync(bool withPassword)
	{
		var email = $"delete-personal-data-{Guid.NewGuid():N}@example.com";
		NorseUser user = new() { UserName = email, Email = email };
		var userManager = fixture.CreateUserManager();
		(await (withPassword ?
			userManager.CreateAsync(user, Password) :
			userManager.CreateAsync(user))).Succeeded.ShouldBeTrue();
		return user.Id;
	}

	/// <summary>A fresh read of the user through a new scope's store, or <see langword="null" /> once it is gone.</summary>
	async Task<NorseUser?> RereadAsync(Guid userId) =>
		await fixture.CreateUserStore().FindByIdAsync(userId.ToString(), Cancellation);

	/// <summary>
	///     Whether the user's row is still there, on a fresh context and without materializing it: past the key's
	///     destruction a store read throws <see cref="KeyDestroyedException" />.
	/// </summary>
	async Task<bool> RowExistsAsync(Guid userId)
	{
		var (context, _) = await fixture.CreateScopeAsync();
		return await context.Users.AnyAsync(u => u.Id == userId, Cancellation);
	}

	static string NextUrlOf(Outcome<NavigationResult> outcome)
	{
		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		return success.Value.NextUrl;
	}
}
