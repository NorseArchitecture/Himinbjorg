using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;

namespace Norse.Identity.Web.Server.Tests;

public sealed class NorseUserManagerTests
{
	// The wired-not-designed test for the scope chokepoint: NO manual SubjectCryptoScope anywhere in
	// this test. TestUserManager runs with ProtectPersonalData off, so no protector participates here --
	// the substituted store's CreateAsync/UpdateAsync captures SubjectCryptoScope.CurrentSubject at
	// invocation time, proving the manager itself establishes the ambient subject around the base call.
	// The composition-level proof -- that a real NorsePersonalDataProtector genuinely rides this scope
	// end to end -- lands with Task 18's real-DI Postgres fixture.
	[Fact]
	async Task Create_through_the_manager_establishes_the_scope_without_any_manual_begin()
	{
		// Arrange a real NorseUserManager over an NSubstitute IUserStore whose CreateAsync captures
		// SubjectCryptoScope.CurrentSubject at invocation time (the moment Identity's store would
		// call the protector). Reuse/extend the project's manager-construction helper.
		Guid? observed = null;
		var store = Substitute.For<IUserStore<NorseUser>>();
		store.CreateAsync(Arg.Any<NorseUser>(), Arg.Any<CancellationToken>())
			.Returns(_ =>
			{
				observed = SubjectCryptoScope.CurrentSubject;
				return IdentityResult.Success;
			});
		using var manager = TestUserManager.Create(store); // helper: real NorseUserManager, substituted collaborators

		NorseUser user = new() { UserName = "buvy@example.com", Email = "buvy@example.com" };
		var result = await manager.CreateAsync(user);

		result.Succeeded.ShouldBeTrue();
		user.Id.ShouldNotBe(Guid.Empty); // id assigned before the store ran
		observed.ShouldBe(user.Id); // ambient subject was live inside the store call
		SubjectCryptoScope.CurrentSubject.ShouldBeNull(); // and restored after
	}

	[Fact]
	async Task Update_through_the_manager_establishes_the_scope_around_the_store_write()
	{
		Guid? observed = null;
		var store = Substitute.For<IUserStore<NorseUser>>();
		store.UpdateAsync(Arg.Any<NorseUser>(), Arg.Any<CancellationToken>())
			.Returns(_ =>
			{
				observed = SubjectCryptoScope.CurrentSubject;
				return IdentityResult.Success;
			});
		store.GetUserIdAsync(Arg.Any<NorseUser>(), Arg.Any<CancellationToken>())
			.Returns(call => call.Arg<NorseUser>()!.Id.ToString());
		using var manager = TestUserManager.Create(store);

		NorseUser user = new() { Id = Guid.NewGuid(), UserName = "buvy@example.com" };
		var result = await manager.UpdateAsync(user);

		result.Succeeded.ShouldBeTrue();
		observed.ShouldBe(user.Id);
	}

	// The empty-subject guard: an unsaved user (Guid.Empty) must never establish an ambient scope --
	// that would mint a DEK for nobody, the exact silent fallback the seam forbids. The store must never
	// even be asked.
	[Fact]
	async Task Update_with_an_empty_id_throws_before_the_store_is_ever_called()
	{
		var store = Substitute.For<IUserStore<NorseUser>>();
		using var manager = TestUserManager.Create(store);

		NorseUser user = new() { Id = Guid.Empty, UserName = "buvy@example.com" };

		await Should.ThrowAsync<InvalidOperationException>(() => manager.UpdateAsync(user));
		await store.DidNotReceiveWithAnyArgs().UpdateAsync(default!, TestContext.Current.CancellationToken);
	}

	// The lossless key provisioning (IAuthenticatorKeyProvisioning): the setup page loads twice (prerender, then
	// interactive), so a missing key is provisioned once and every later load answers that same key without a write.
	[Fact]
	async Task Provisioning_a_missing_key_does_not_rotate_the_stamp()
	{
		var store = AuthenticatorStore();
		var keys = (IUserAuthenticatorKeyStore<NorseUser>)store;
		string? stored = null;
		keys.GetAuthenticatorKeyAsync(Arg.Any<NorseUser>(), Arg.Any<CancellationToken>()).Returns(_ => stored);
		keys.SetAuthenticatorKeyAsync(Arg.Any<NorseUser>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
			.Returns(call =>
			{
				stored = call.ArgAt<string>(1);
				return Task.CompletedTask;
			});
		store.UpdateAsync(Arg.Any<NorseUser>(), Arg.Any<CancellationToken>()).Returns(IdentityResult.Success);
		using var manager = TestUserManager.Create(store);
		NorseUser user = new() { Id = Guid.CreateVersion7(), UserName = "buvy@example.com" };

		var (result, key) = await manager.ProvisionAuthenticatorKeyAsync(user);

		result.Succeeded.ShouldBeTrue();
		key.ShouldNotBeNullOrWhiteSpace();
		key.ShouldBe(stored);
		await keys.Received(1).SetAuthenticatorKeyAsync(user, key, Arg.Any<CancellationToken>());
		await store.Received(1).UpdateAsync(user, Arg.Any<CancellationToken>());
		await ((IUserSecurityStampStore<NorseUser>)store).DidNotReceiveWithAnyArgs()
			.SetSecurityStampAsync(default!, default!, TestContext.Current.CancellationToken);
	}

	[Fact]
	async Task Provisioning_an_existing_key_writes_nothing()
	{
		var store = AuthenticatorStore();
		var keys = (IUserAuthenticatorKeyStore<NorseUser>)store;
		keys.GetAuthenticatorKeyAsync(Arg.Any<NorseUser>(), Arg.Any<CancellationToken>()).Returns("existing-key");
		using var manager = TestUserManager.Create(store);
		NorseUser user = new() { Id = Guid.CreateVersion7(), UserName = "buvy@example.com" };

		var (result, key) = await manager.ProvisionAuthenticatorKeyAsync(user);

		result.ShouldBeSameAs(IdentityResult.Success);
		key.ShouldBe("existing-key");
		await keys.DidNotReceiveWithAnyArgs().SetAuthenticatorKeyAsync(default!, default!, TestContext.Current.CancellationToken);
		await store.DidNotReceiveWithAnyArgs().UpdateAsync(default!, TestContext.Current.CancellationToken);
		await ((IUserSecurityStampStore<NorseUser>)store).DidNotReceiveWithAnyArgs()
			.SetSecurityStampAsync(default!, default!, TestContext.Current.CancellationToken);
	}

	// The double setup load: the prerender provisions, the interactive render (a fresh read of the same row) answers
	// the key the prerender stored, so the QR code the user scans is the key that verifies.
	[Fact]
	async Task A_double_setup_load_provisions_once_and_answers_the_same_key()
	{
		var store = AuthenticatorStore();
		var keys = (IUserAuthenticatorKeyStore<NorseUser>)store;
		string? stored = null;
		keys.GetAuthenticatorKeyAsync(Arg.Any<NorseUser>(), Arg.Any<CancellationToken>()).Returns(_ => stored);
		keys.SetAuthenticatorKeyAsync(Arg.Any<NorseUser>(), Arg.Any<string>(), Arg.Any<CancellationToken>())
			.Returns(call =>
			{
				stored = call.ArgAt<string>(1);
				return Task.CompletedTask;
			});
		store.UpdateAsync(Arg.Any<NorseUser>(), Arg.Any<CancellationToken>()).Returns(IdentityResult.Success);
		using var manager = TestUserManager.Create(store);
		var id = Guid.CreateVersion7();

		var (prerendered, prerenderKey) =
			await manager.ProvisionAuthenticatorKeyAsync(new() { Id = id, UserName = "buvy@example.com" });
		var (interactive, interactiveKey) =
			await manager.ProvisionAuthenticatorKeyAsync(new() { Id = id, UserName = "buvy@example.com" });

		prerendered.Succeeded.ShouldBeTrue();
		interactive.Succeeded.ShouldBeTrue();
		interactiveKey.ShouldBe(prerenderKey);
		await keys.ReceivedWithAnyArgs(1).SetAuthenticatorKeyAsync(default!, default!, TestContext.Current.CancellationToken);
		await store.ReceivedWithAnyArgs(1).UpdateAsync(default!, TestContext.Current.CancellationToken);
	}

	// A write that reports success but leaves no key stored is refused, never answered with a key nobody stored: the
	// QR code would carry a secret the verify step can never match.
	[Fact]
	async Task A_write_that_leaves_no_key_stored_fails_closed()
	{
		var store = AuthenticatorStore();
		((IUserAuthenticatorKeyStore<NorseUser>)store)
			.GetAuthenticatorKeyAsync(Arg.Any<NorseUser>(), Arg.Any<CancellationToken>()).Returns((string?)null);
		store.UpdateAsync(Arg.Any<NorseUser>(), Arg.Any<CancellationToken>()).Returns(IdentityResult.Success);
		using var manager = TestUserManager.Create(store);

		var (result, key) = await manager.ProvisionAuthenticatorKeyAsync(
			new() { Id = Guid.CreateVersion7(), UserName = "buvy@example.com" });

		result.Succeeded.ShouldBeFalse();
		result.Errors.ShouldHaveSingleItem().Code.ShouldBe(NorseIdentityErrorCodes.AuthenticatorKeyNotStored);
		key.ShouldBeEmpty();
	}

	[Fact]
	async Task Provisioning_answers_the_update_result_untouched()
	{
		var store = AuthenticatorStore();
		((IUserAuthenticatorKeyStore<NorseUser>)store)
			.GetAuthenticatorKeyAsync(Arg.Any<NorseUser>(), Arg.Any<CancellationToken>()).Returns((string?)null);
		var indeterminate = IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome });
		store.UpdateAsync(Arg.Any<NorseUser>(), Arg.Any<CancellationToken>()).Returns(indeterminate);
		using var manager = TestUserManager.Create(store);

		var (result, _) = await manager.ProvisionAuthenticatorKeyAsync(
			new() { Id = Guid.CreateVersion7(), UserName = "buvy@example.com" });

		result.ShouldBeSameAs(indeterminate);
	}

	static IUserStore<NorseUser> AuthenticatorStore()
	{
		var store = Substitute.For<IUserStore<NorseUser>, IUserAuthenticatorKeyStore<NorseUser>,
			IUserSecurityStampStore<NorseUser>>();
		((IUserSecurityStampStore<NorseUser>)store)
			.GetSecurityStampAsync(Arg.Any<NorseUser>(), Arg.Any<CancellationToken>())
			.Returns("stamp");
		return store;
	}
}
