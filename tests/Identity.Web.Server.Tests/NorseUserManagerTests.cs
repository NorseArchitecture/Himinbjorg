using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Identity.EntityFramework;

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
		user.Id.ShouldNotBe(Guid.Empty);          // id assigned before the store ran
		observed.ShouldBe(user.Id);               // ambient subject was live inside the store call
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
}
