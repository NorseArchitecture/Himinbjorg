using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The passkey sign-in over a real <see cref="NorseUserStore" />, the real managers and the real database ledger, once
///     per provider (the 2026-10-24 explicit-writes invariant): the sign count the authenticator reported is stored, and
///     the <c>users</c> record versions nothing, because passkeys are not temporal and nothing on <c>users</c> changed.
///     The WebAuthn handler is substituted with the real one's success shape -- the user and the stored passkey read
///     through the store, the new sign count set -- since a TestServer cannot produce a signed assertion.
/// </summary>
/// <remarks>
///     Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///     records: xUnit discovers them on each <see langword="sealed" /> provider class.
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class PasskeySignInWritePathSuite(IdentityFixture fixture) : IDisposable
{
	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	readonly List<IServiceScope> _scopes = [];

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
		foreach (var scope in _scopes)
			scope.Dispose();
		GC.SuppressFinalize(this);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task A_passkey_sign_in_writes_no_users_history_row()
	{
		fixture.SkipUnlessAvailable();
		var seeded = await fixture.SeedUserAsync($"passkey-sign-in-{Guid.NewGuid():N}@example.com");
		byte[] credentialId = [.. seeded.Id.ToByteArray(), 41];
		var enrolling = fixture.CreateUserManager();
		(await enrolling.AddOrUpdatePasskeyAsync((await enrolling.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull(),
			new(credentialId, [1, 2, 3], DateTimeOffset.UtcNow, 0, ["internal"], true, false, false, [4], [5])))
			.Succeeded.ShouldBeTrue();
		var (context, _) = await fixture.CreateScopeAsync();
		var versionsBefore = await UserVersionsAsync(context, seeded.Id);
		var signIn = SignIn(seeded.Id, credentialId, signCount: 9);

		var ceremony = await signIn.CreatePasskeyRequestOptionsAsync(Cancellation);
		var result = await signIn.PasskeyAssertionSignInAsync("{}", ceremony.State, isPersistent: false, Cancellation);
		var replay = await SignIn(seeded.Id, credentialId, signCount: 10)
			.PasskeyAssertionSignInAsync("{}", ceremony.State, isPersistent: false, Cancellation);

		result.Succeeded.ShouldBeTrue();
		replay.ShouldBe(SignInResult.Failed, "the database ledger refuses the replay, across scopes");
		var rereading = fixture.CreateUserManager();
		var stored = await rereading.GetPasskeyAsync(
			(await rereading.FindByIdAsync(seeded.Id.ToString())).ShouldNotBeNull(), credentialId);
		stored.ShouldNotBeNull().SignCount.ShouldBe(9u, "the sign count updates; the replay wrote nothing");
		(await UserVersionsAsync(context, seeded.Id)).ShouldBe(versionsBefore);
	}

	/// <summary>The number of history versions of <paramref name="userId" />'s <c>users</c> row.</summary>
	/// <param name="context">A context to query through.</param>
	/// <param name="userId">The user.</param>
	protected abstract Task<long> UserVersionsAsync(NorseIdentityDbContext context, Guid userId);

	// One request's sign-in manager, on its own scope: the real managers and the real ledger, with a handler answering
	// what PasskeyHandler answers on a verified assertion.
	NorseSignInManager SignIn(Guid userId, byte[] credentialId, uint signCount)
	{
		var scope = fixture.CreateOwnedScope();
		_scopes.Add(scope);
		var userManager = scope.ServiceProvider.GetRequiredService<UserManager<NorseUser>>();
		var handler = Substitute.For<IPasskeyHandler<NorseUser>>();
		handler.MakeRequestOptionsAsync(null, Arg.Any<HttpContext>()).Returns(new PasskeyRequestOptionsResult
		{
			RequestOptionsJson = "{}",
			AssertionState = $$"""{"challenge":"{{Guid.NewGuid():N}}","userId":null}"""
		});
		handler.PerformAssertionAsync(Arg.Any<PasskeyAssertionContext>()).Returns(async _ =>
		{
			var user = (await userManager.FindByIdAsync(userId.ToString())).ShouldNotBeNull();
			var passkey = (await userManager.GetPasskeyAsync(user, credentialId)).ShouldNotBeNull();
			passkey.SignCount = signCount;
			return PasskeyAssertionResult.Success(passkey, user);
		});
		var signIn = ActivatorUtilities.CreateInstance<NorseSignInManager>(scope.ServiceProvider, userManager, handler);
		signIn.Context = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
		return signIn;
	}
}
