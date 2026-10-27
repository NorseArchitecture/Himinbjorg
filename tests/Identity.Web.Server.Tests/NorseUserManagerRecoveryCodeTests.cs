using Microsoft.AspNetCore.Identity;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The lossless recovery-code replacement (<see cref="IRecoveryCodeReplacement" />): a real
///     <see cref="NorseUserManager" /> over a substituted store, so the update's own result reaches the caller.
/// </summary>
public sealed class NorseUserManagerRecoveryCodeTests
{
	readonly IUserStore<NorseUser> _store = Substitute.For<IUserStore<NorseUser>,
		IUserTwoFactorRecoveryCodeStore<NorseUser>, IUserSecurityStampStore<NorseUser>>();

	readonly NorseUser _user = new() { Id = Guid.CreateVersion7(), UserName = "buvy@example.com" };

	public NorseUserManagerRecoveryCodeTests() =>
		((IUserSecurityStampStore<NorseUser>)_store)
			.GetSecurityStampAsync(Arg.Any<NorseUser>(), Arg.Any<CancellationToken>())
			.Returns("stamp");

	static IdentityResult Indeterminate =>
		IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome });

	[Fact]
	async Task ReplaceRecoveryCodesAsync_returns_the_update_result_untouched_with_the_generated_codes()
	{
		var indeterminate = Indeterminate;
		_store.UpdateAsync(_user, Arg.Any<CancellationToken>()).Returns(indeterminate);
		using var manager = TestUserManager.Create(_store);

		var (result, codes) = await manager.ReplaceRecoveryCodesAsync(_user, 10);

		result.ShouldBeSameAs(indeterminate);
		codes.Length.ShouldBe(10);
		codes.Distinct(StringComparer.Ordinal).Count().ShouldBe(10);
		await ((IUserTwoFactorRecoveryCodeStore<NorseUser>)_store).Received(1).ReplaceCodesAsync(_user,
			Arg.Is<IEnumerable<string>>(replaced => replaced.SequenceEqual(codes)), Arg.Any<CancellationToken>());
	}

	[Fact]
	async Task GenerateNewTwoFactorRecoveryCodesAsync_delegates_to_the_lossless_path()
	{
		_store.UpdateAsync(_user, Arg.Any<CancellationToken>()).Returns(Indeterminate, IdentityResult.Success);
		using var manager = TestUserManager.Create(_store);

		(await manager.GenerateNewTwoFactorRecoveryCodesAsync(_user, 10)).ShouldBeNull();
		var codes = (await manager.GenerateNewTwoFactorRecoveryCodesAsync(_user, 10)).ShouldNotBeNull().ToArray();

		codes.Length.ShouldBe(10);
		await ((IUserTwoFactorRecoveryCodeStore<NorseUser>)_store).Received(1).ReplaceCodesAsync(_user,
			Arg.Is<IEnumerable<string>>(replaced => replaced.SequenceEqual(codes)), Arg.Any<CancellationToken>());
	}
}
