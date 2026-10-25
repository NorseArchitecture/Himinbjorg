using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Primitives;

namespace Norse.Identity.Outcomes.Tests;

/// <summary><c>userManager.Outcome</c>, one fact per view method, against a substituted manager.</summary>
public sealed class UserManagerOutcomeViewTests
{
	readonly UserManager<NorseUser> _userManager = Substitute.For<UserManager<NorseUser>>(
		Substitute.For<IUserStore<NorseUser>>(), null!, new PasswordHasher<NorseUser>(),
		Array.Empty<IUserValidator<NorseUser>>(), Array.Empty<IPasswordValidator<NorseUser>>(),
		new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null!,
		NullLogger<UserManager<NorseUser>>.Instance);

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task CreateAsync_maps_the_IdentityResult()
	{
		NorseUser created = new() { Email = "created@example.com" }, refused = new() { Email = "refused@example.com" };
		_userManager.CreateAsync(created, "pw").Returns(IdentityResult.Success);
		_userManager.CreateAsync(refused, "pw").Returns(IdentityResult.Failed(new IdentityErrorDescriber().DuplicateEmail("x")));

		(await _userManager.Outcome.CreateAsync(created, "pw", Cancellation)).TryGetValue(out Success<Unit> _)
			.ShouldBeTrue();
		Category(await _userManager.Outcome.CreateAsync(refused, "pw", Cancellation)).ShouldBe(ErrorCategory.Conflict);
	}

	[Fact]
	async Task CreateAsync_classifies_an_indeterminate_write()
	{
		NorseUser user = new();
		_userManager.CreateAsync(user, "pw")
			.ThrowsAsync(new IndeterminateWriteException("the create", new TimeoutException()));

		Category(await _userManager.Outcome.CreateAsync(user, "pw", Cancellation)).ShouldBe(ErrorCategory.Indeterminate);
	}

	[Fact]
	async Task FindByEmailAsync_answers_the_user_NotFound_or_Erased()
	{
		NorseUser user = new() { Email = "found@example.com" };
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.FindByEmailAsync("found@example.com").Returns(user);
		_userManager.FindByEmailAsync("missing@example.com").Returns((NorseUser?)null);
		_userManager.FindByEmailAsync("erased@example.com").ThrowsAsync(new KeyDestroyedException(receipt));

		(await _userManager.Outcome.FindByEmailAsync("found@example.com", Cancellation))
			.TryGetValue(out Success<NorseUser> found).ShouldBeTrue();
		found.Value.ShouldBeSameAs(user);
		Category(await _userManager.Outcome.FindByEmailAsync("missing@example.com", Cancellation))
			.ShouldBe(ErrorCategory.NotFound);
		var erased = await _userManager.Outcome.FindByEmailAsync("erased@example.com", Cancellation);
		erased.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Erased);
		failed.Problem.Receipt.ShouldBe(receipt);
	}

	static ErrorCategory Category<T>(Outcome<T> outcome)
		where T : notnull
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem.Category;
	}
}
