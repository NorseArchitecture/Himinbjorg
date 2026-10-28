using System.Data.Common;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.TwoFactor;

namespace Norse.Identity.Web.Server.Tests.TwoFactor;

/// <summary>
///     The two-factor handlers over a real <see cref="NorseUserStore" /> and real managers, once per provider: after a
///     stamp-rotating write whose outcome the handler could not take at its word, the refreshed sign-in carries the
///     stamp the database holds, because the refresh uses a re-read user (T3-35), never the as-read instance a failed
///     or indeterminate flush may have poisoned. And the authenticator key's first provisioning is a conditional write,
///     so two concurrent setups answer the one key that is stored (the 4.1 carry, ruled for 4.4). The disable, the
///     4.5 rotating write, is pinned the same way.
/// </summary>
/// <remarks>
///     <para>
///         The failure seam is <see cref="CommitFailureInterceptor" /> on the handler's own context. It has no
///         "indeterminate and not landed" mode, and the re-read makes the claim match the database in every case.
///     </para>
///     <para>
///         Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///         records: xUnit discovers them on each <see langword="sealed" /> provider class.
///     </para>
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class StampRefreshSuite(IdentityFixture fixture) : IDisposable
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	const string AuthenticatorProvider = "[AspNetUserStore]";
	const string AuthenticatorKeyName = "AuthenticatorKey";

	readonly List<IDisposable> _owned = [];

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
		foreach (var owned in _owned)
			owned.Dispose();
		GC.SuppressFinalize(this);
	}

	// The enable's flush carries the users stamp marker, so a lost acknowledgement alone resolves as committed. A writer
	// committing in the window, moving both the concurrency stamp and the security stamp, leaves a third stamp: the
	// flush answers Indeterminate and poisons the instance, which holds the enable's stamp, not the database's.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_enable_whose_commit_lands_but_reports_indeterminate_refreshes_with_the_stored_stamp()
	{
		fixture.SkipUnlessAvailable();
		var (userId, key) = await SeedWithKeyAsync("enable-indeterminate@example.com");
		// The column is 32 characters, Identity's base32 stamp length: a GUID in "N" format fits it exactly.
		var writersStamp = Guid.NewGuid().ToString("N").ToUpperInvariant();
		CommitFailureInterceptor interceptor = new(CommitFailure.AfterCommit, async cancellationToken =>
		{
			await using var writer = fixture.CreateContext();
			(await writer.Users
				.Where(u => u.Id == userId)
				.ExecuteUpdateAsync(setters => setters.SetProperty(static u => u.ConcurrencyStamp, Guid.NewGuid().ToString()),
					cancellationToken))
				.ShouldBe(1, "the concurrent writer commits between the commit and the verification");
			(await RotateStoredSecurityStampAsync(writer, userId, writersStamp, cancellationToken)).ShouldBe(1);
		});
		var request = await SignedInRequestAsync(userId, interceptor);

		var outcome = await request.EnableAsync(TotpCode.Now(key));

		interceptor.Fired.ShouldBe(1);
		BaseRequest.ValueOf(outcome).NextUrl.ShouldBe("/Account/Manage/TwoFactorAuthentication",
			"an indeterminate enable answers the two-factor page with no status key");
		var stored = await RereadAsync(userId);
		stored.TwoFactorEnabled.ShouldBeTrue("the enable committed");
		stored.SecurityStamp.ShouldBe(writersStamp);
		request.RefreshedStamp().ShouldBe(stored.SecurityStamp);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_code_step_that_fails_definitely_after_enable_refreshes_with_the_stored_stamp()
	{
		fixture.SkipUnlessAvailable();
		var (userId, key) = await SeedWithKeyAsync("code-step-definite@example.com");
		var stampBefore = (await RereadAsync(userId)).SecurityStamp;
		CommitFailureInterceptor interceptor = new(CommitFailure.BeforeCommit, pass: 1);
		var request = await SignedInRequestAsync(userId, interceptor);

		var outcome = await request.EnableAsync(TotpCode.Now(key));

		interceptor.Fired.ShouldBe(1);
		interceptor.Commits.ShouldBe(2, "the enable, then the failed code step");
		BaseRequest.ValueOf(outcome).NextUrl.ShouldBe("/Account/Manage/TwoFactorAuthentication?status=recovery-codes-failed");
		var stored = await RereadAsync(userId);
		stored.TwoFactorEnabled.ShouldBeTrue("the enable committed");
		stored.SecurityStamp.ShouldNotBe(stampBefore, "the enable rotated the stamp");
		(await fixture.CreateUserManager().CountRecoveryCodesAsync(stored)).ShouldBe(0, "the code step wrote nothing");
		request.RefreshedStamp().ShouldBe(stored.SecurityStamp);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_successful_disable_rotates_the_stored_stamp()
	{
		fixture.SkipUnlessAvailable();
		var userId = await SeedWithTwoFactorAsync("disable-success@example.com");
		var stampBefore = (await RereadAsync(userId)).SecurityStamp;
		CommitFailureInterceptor interceptor = new(CommitFailure.None);
		var request = await SignedInRequestAsync(userId, interceptor);

		var outcome = await request.DisableAsync();

		interceptor.Commits.ShouldBe(1, "the disable is the one write");
		BaseRequest.ValueOf(outcome).NextUrl.ShouldBe("/Account/Manage/TwoFactorAuthentication?status=two-factor-disabled");
		var stored = await RereadAsync(userId);
		stored.TwoFactorEnabled.ShouldBeFalse();
		stored.SecurityStamp.ShouldNotBe(stampBefore, "the disable rotated the stamp");
		request.RefreshedStamp().ShouldBe(stored.SecurityStamp);
	}

	// The enable fact's shape, for the disable: a writer committing in the window leaves a third stamp, so the
	// disable answers Indeterminate and its as-read instance holds a stamp the database never kept.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_indeterminate_disable_refreshes_with_the_stored_stamp()
	{
		fixture.SkipUnlessAvailable();
		var userId = await SeedWithTwoFactorAsync("disable-indeterminate@example.com");
		var writersStamp = Guid.NewGuid().ToString("N").ToUpperInvariant();
		CommitFailureInterceptor interceptor = new(CommitFailure.AfterCommit, async cancellationToken =>
		{
			await using var writer = fixture.CreateContext();
			(await writer.Users
				.Where(u => u.Id == userId)
				.ExecuteUpdateAsync(setters => setters.SetProperty(static u => u.ConcurrencyStamp, Guid.NewGuid().ToString()),
					cancellationToken))
				.ShouldBe(1, "the concurrent writer commits between the commit and the verification");
			(await RotateStoredSecurityStampAsync(writer, userId, writersStamp, cancellationToken)).ShouldBe(1);
		});
		var request = await SignedInRequestAsync(userId, interceptor);

		var outcome = await request.DisableAsync();

		interceptor.Fired.ShouldBe(1);
		BaseRequest.ValueOf(outcome).NextUrl.ShouldBe("/Account/Manage/TwoFactorAuthentication",
			"an indeterminate disable answers the two-factor page with no status key");
		var stored = await RereadAsync(userId);
		stored.TwoFactorEnabled.ShouldBeFalse("the disable committed");
		stored.SecurityStamp.ShouldBe(writersStamp);
		request.RefreshedStamp().ShouldBe(stored.SecurityStamp);
	}

	// The 4.1 carry, ruled for 4.4: two tabs opening the setup page for the first time must not each mint a key with the
	// last writer winning, or the key one tab's QR code shows is not the key that verifies. Both reads of "no key" are
	// forced to happen before either write, so the race is real.
	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Two_concurrent_first_setups_answer_the_same_stored_key()
	{
		fixture.SkipUnlessAvailable();
		var seeded = await fixture.SeedUserAsync("concurrent-setup@example.com");
		var (context, _) = await fixture.CreateScopeAsync();
		var versionsBefore = await UserVersionsAsync(context, seeded.Id);
		var stampBefore = (await RereadAsync(seeded.Id)).SecurityStamp;
		Rendezvous rendezvous = new(2);
		var first = await ArmedManagerAsync(seeded.Id, rendezvous);
		var second = await ArmedManagerAsync(seeded.Id, rendezvous);

		var answers = await Task.WhenAll(
			first.Manager.Outcome.ProvisionAuthenticatorKeyAsync(first.User, Cancellation).AsTask(),
			second.Manager.Outcome.ProvisionAuthenticatorKeyAsync(second.User, Cancellation).AsTask());

		rendezvous.Arrived.ShouldBe(2, "both setups read no key before either wrote");
		var keys = answers.Select(BaseRequest.ValueOf).ToArray();
		keys[1].ShouldBe(keys[0]);
		await using var verify = fixture.CreateContext();
		(await verify.UserTokens
				.AsNoTracking()
				.CountAsync(t => t.UserId == seeded.Id && t.LoginProvider == AuthenticatorProvider && t.Name == AuthenticatorKeyName,
					Cancellation))
			.ShouldBe(1);
		var reread = await RereadAsync(seeded.Id);
		(await fixture.CreateUserManager().GetAuthenticatorKeyAsync(reread)).ShouldBe(keys[0]);
		reread.SecurityStamp.ShouldBe(stampBefore, "provisioning never rotates the stamp");
		(await UserVersionsAsync(context, seeded.Id)).ShouldBe(versionsBefore, "a key is a token, never users history");
	}

	/// <summary>How many superseded versions of one user row the history holds.</summary>
	protected abstract Task<long> UserVersionsAsync(NorseIdentityDbContext context, Guid userId);

	/// <summary>Sets one user's stored security stamp on the <c>user_credentials</c> fragment, as a concurrent writer.</summary>
	protected abstract Task<int> RotateStoredSecurityStampAsync(NorseIdentityDbContext context, Guid userId, string stamp,
		CancellationToken cancellationToken);

	/// <summary>A seeded user with a provisioned, not yet verified, authenticator key.</summary>
	async Task<(Guid UserId, string Key)> SeedWithKeyAsync(string email)
	{
		var seeded = await fixture.SeedUserAsync(email);
		var userManager = fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		return (seeded.Id, BaseRequest.ValueOf(await userManager.Outcome.ProvisionAuthenticatorKeyAsync(user, Cancellation)));
	}

	/// <summary>A seeded user with two-factor authentication enabled.</summary>
	async Task<Guid> SeedWithTwoFactorAsync(string email)
	{
		var seeded = await fixture.SeedUserAsync(email);
		var userManager = fixture.CreateUserManager();
		var user = (await userManager.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull();
		BaseRequest.ValueOf(await userManager.Outcome.SetTwoFactorEnabledAsync(user, true, Cancellation));
		return seeded.Id;
	}

	async Task<NorseUser> RereadAsync(Guid userId) =>
		(await fixture.CreateUserManager().FindByIdAsync(userId.ToString())).ShouldNotBeNull();

	/// <summary>
	///     A request signed in as the user, its manager over a store whose context carries <paramref name="interceptor" />.
	///     A refresh only re-issues a cookie the request already carries, so a first request signs in and its cookie
	///     rides the second, where the handler runs.
	/// </summary>
	async Task<SignedInRequest> SignedInRequestAsync(Guid userId, CommitFailureInterceptor interceptor)
	{
		var context = fixture.CreateContext(interceptor);
		_owned.Add(context);
		var userManager = fixture.CreateUserManager(new NorseUserStore(context, new()));
		var signInManager = fixture.CreateSignInManager(userManager);
		var signInScope = fixture.CreateOwnedScope();
		_owned.Add(signInScope);
		DefaultHttpContext signedIn = new() { RequestServices = signInScope.ServiceProvider };
		signInManager.Context = signedIn;
		await signInManager.SignInAsync((await userManager.FindByIdAsync(userId.ToString())).ShouldNotBeNull(), isPersistent: false);
		var requestScope = fixture.CreateOwnedScope();
		_owned.Add(requestScope);
		DefaultHttpContext http = new() { RequestServices = requestScope.ServiceProvider };
		http.Request.Headers.Cookie = TwoFactorHarness.CookieOf(signedIn.Response.Headers.SetCookie.Single()!);
		signInManager.Context = http;
		return new(userId, userManager, signInManager, http, requestScope.ServiceProvider);
	}

	/// <summary>A real manager over a store whose context waits at its first key read until every setup has read.</summary>
	async Task<(NorseUserManager Manager, NorseUser User)> ArmedManagerAsync(Guid userId, Rendezvous rendezvous)
	{
		KeyReadRendezvous interceptor = new(rendezvous);
		var context = fixture.CreateContext(interceptor);
		_owned.Add(context);
		var userManager = fixture.CreateUserManager(new NorseUserStore(context, new()));
		var user = (await userManager.FindByIdAsync(userId.ToString())).ShouldNotBeNull();
		interceptor.Armed = true;
		return (userManager, user);
	}

	/// <summary>The second request of <see cref="SignedInRequestAsync" />, and what its handler refreshed.</summary>
	sealed record SignedInRequest(
		Guid UserId,
		NorseUserManager UserManager,
		NorseSignInManager SignInManager,
		DefaultHttpContext Http,
		IServiceProvider Services)
	{
		/// <summary>Runs <see cref="EnableAuthenticatorHandler" /> on this request.</summary>
		public ValueTask<Outcome<NavigationResult>> EnableAsync(string code)
		{
			var accessor = Substitute.For<IHttpContextAccessor>();
			accessor.HttpContext.Returns(Http);
			EnableAuthenticatorHandler handler = new(new AccountCaller(FakePrincipal.For(UserId), UserManager), UserManager,
				SignInManager, new(Substitute.For<IDeferredSignIn>(), accessor), accessor,
				Services.GetRequiredService<IDataProtectionProvider>(),
				Services.GetRequiredService<ILogger<EnableAuthenticatorHandler>>());
			return handler.Handle(new(new() { Code = code }), Cancellation);
		}

		/// <summary>Runs <see cref="DisableTwoFactorHandler" /> on this request.</summary>
		public ValueTask<Outcome<NavigationResult>> DisableAsync()
		{
			var accessor = Substitute.For<IHttpContextAccessor>();
			accessor.HttpContext.Returns(Http);
			DisableTwoFactorHandler handler = new(new AccountCaller(FakePrincipal.For(UserId), UserManager), UserManager,
				SignInManager, new(Substitute.For<IDeferredSignIn>(), accessor), accessor);
			return handler.Handle(new(Unit.Value), Cancellation);
		}

		/// <summary>The security-stamp claim of the identity cookie the refresh wrote on this request.</summary>
		public string? RefreshedStamp()
		{
			var options = Services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
				.Get(IdentityConstants.ApplicationScheme);
			var setCookie = Http.Response.Headers.SetCookie
				.ShouldHaveSingleItem("the refresh re-issues the identity cookie")!;
			var ticket = options.TicketDataFormat
				.Unprotect(TwoFactorHarness.CookieOf(setCookie)[(options.Cookie.Name!.Length + 1)..])
				.ShouldNotBeNull();
			var claimType = Services.GetRequiredService<IOptions<IdentityOptions>>().Value.ClaimsIdentity.SecurityStampClaimType;
			return ticket.Principal.FindFirst(claimType)?.Value;
		}
	}

	/// <summary>Counts arrivals and releases every party once all have arrived.</summary>
	/// <param name="parties">How many must arrive.</param>
	sealed class Rendezvous(int parties)
	{
		readonly TaskCompletionSource _all = new(TaskCreationOptions.RunContinuationsAsynchronously);
		int _arrived;

		/// <summary>How many have arrived.</summary>
		public int Arrived => Volatile.Read(ref _arrived);

		/// <summary>Arrives, then waits for the rest; a party left alone fails rather than hangs.</summary>
		public async Task ArriveAndWaitAsync(CancellationToken cancellationToken)
		{
			if (Interlocked.Increment(ref _arrived) == parties)
				_all.TrySetResult();
			await _all.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);
		}
	}

	/// <summary>Holds the first authenticator-key read after arming at <paramref name="rendezvous" />.</summary>
	sealed class KeyReadRendezvous(Rendezvous rendezvous) : DbCommandInterceptor
	{
		int _waited;

		/// <summary>Set once the user is read, so only the provisioning's own key read waits.</summary>
		public bool Armed { get; set; }

		public override async ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData,
			DbDataReader result, CancellationToken cancellationToken = default)
		{
			if (Armed && IsTokenRead(command.CommandText) && Interlocked.Exchange(ref _waited, 1) is 0)
				await rendezvous.ArriveAndWaitAsync(cancellationToken);
			return result;
		}

		static bool IsTokenRead(string sql) =>
			sql.StartsWith("SELECT", StringComparison.OrdinalIgnoreCase) &&
			(sql.Contains("user_tokens", StringComparison.Ordinal) || sql.Contains("[UserTokens]", StringComparison.Ordinal));
	}
}
