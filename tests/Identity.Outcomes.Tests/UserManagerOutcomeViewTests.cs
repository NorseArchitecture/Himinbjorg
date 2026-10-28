using System.Security.Claims;
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

	[Fact]
	async Task GetUserAsync_answers_the_user_NotFound_or_Erased()
	{
		NorseUser user = new() { Email = "found@example.com" };
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		ClaimsPrincipal found = Principal("found"), missing = Principal("missing"), erased = Principal("erased");
		_userManager.GetUserAsync(found).Returns(user);
		_userManager.GetUserAsync(missing).Returns((NorseUser?)null);
		_userManager.GetUserAsync(erased).ThrowsAsync(new KeyDestroyedException(receipt));

		(await _userManager.Outcome.GetUserAsync(found, Cancellation))
			.TryGetValue(out Success<NorseUser> success).ShouldBeTrue();
		success.Value.ShouldBeSameAs(user);
		Category(await _userManager.Outcome.GetUserAsync(missing, Cancellation)).ShouldBe(ErrorCategory.NotFound);
		(await _userManager.Outcome.GetUserAsync(erased, Cancellation)).TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Erased);
		failed.Problem.Receipt.ShouldBe(receipt);
	}

	[Fact]
	async Task FindByIdAsync_answers_the_user_NotFound_or_Erased()
	{
		NorseUser user = new() { Id = Guid.CreateVersion7() };
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.FindByIdAsync("found").Returns(user);
		_userManager.FindByIdAsync("missing").Returns((NorseUser?)null);
		_userManager.FindByIdAsync("erased").ThrowsAsync(new KeyDestroyedException(receipt));

		(await _userManager.Outcome.FindByIdAsync("found", Cancellation))
			.TryGetValue(out Success<NorseUser> success).ShouldBeTrue();
		success.Value.ShouldBeSameAs(user);
		Category(await _userManager.Outcome.FindByIdAsync("missing", Cancellation)).ShouldBe(ErrorCategory.NotFound);
		(await _userManager.Outcome.FindByIdAsync("erased", Cancellation)).TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Erased);
		failed.Problem.Receipt.ShouldBe(receipt);
	}

	[Fact]
	async Task ResetPasswordAsync_maps_InvalidToken_to_InvalidCredentials_and_password_rules_to_Validation()
	{
		NorseUser user = new();
		IdentityErrorDescriber describer = new();
		_userManager.ResetPasswordAsync(user, "good", "Strong-1!").Returns(IdentityResult.Success);
		_userManager.ResetPasswordAsync(user, "stale", "Strong-1!").Returns(IdentityResult.Failed(describer.InvalidToken()));
		_userManager.ResetPasswordAsync(user, "good", "weak")
			.Returns(IdentityResult.Failed(describer.PasswordTooShort(8), describer.PasswordRequiresDigit()));

		(await _userManager.Outcome.ResetPasswordAsync(user, "good", "Strong-1!", Cancellation))
			.TryGetValue(out Success<Unit> _).ShouldBeTrue();
		Category(await _userManager.Outcome.ResetPasswordAsync(user, "stale", "Strong-1!", Cancellation))
			.ShouldBe(ErrorCategory.InvalidCredentials);
		Category(await _userManager.Outcome.ResetPasswordAsync(user, "good", "weak", Cancellation))
			.ShouldBe(ErrorCategory.Validation);
	}

	[Fact]
	async Task ConfirmEmailAsync_maps_InvalidToken_to_InvalidCredentials()
	{
		NorseUser user = new();
		_userManager.ConfirmEmailAsync(user, "good").Returns(IdentityResult.Success);
		_userManager.ConfirmEmailAsync(user, "stale").Returns(IdentityResult.Failed(new IdentityErrorDescriber().InvalidToken()));

		(await _userManager.Outcome.ConfirmEmailAsync(user, "good", Cancellation))
			.TryGetValue(out Success<Unit> _).ShouldBeTrue();
		Category(await _userManager.Outcome.ConfirmEmailAsync(user, "stale", Cancellation))
			.ShouldBe(ErrorCategory.InvalidCredentials);
	}

	[Fact]
	async Task ChangeEmailAsync_maps_DuplicateEmail_to_Conflict_and_an_indeterminate_write_to_Indeterminate()
	{
		NorseUser user = new();
		_userManager.ChangeEmailAsync(user, "new@example.com", "good").Returns(IdentityResult.Success);
		_userManager.ChangeEmailAsync(user, "taken@example.com", "good")
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().DuplicateEmail("taken@example.com")));
		_userManager.ChangeEmailAsync(user, "unsure@example.com", "good")
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));
		_userManager.ChangeEmailAsync(user, "thrown@example.com", "good")
			.ThrowsAsync(new IndeterminateWriteException("the email change", new TimeoutException()));

		(await _userManager.Outcome.ChangeEmailAsync(user, "new@example.com", "good", Cancellation))
			.TryGetValue(out Success<Unit> _).ShouldBeTrue();
		Category(await _userManager.Outcome.ChangeEmailAsync(user, "taken@example.com", "good", Cancellation))
			.ShouldBe(ErrorCategory.Conflict);
		Category(await _userManager.Outcome.ChangeEmailAsync(user, "unsure@example.com", "good", Cancellation))
			.ShouldBe(ErrorCategory.Indeterminate);
		Category(await _userManager.Outcome.ChangeEmailAsync(user, "thrown@example.com", "good", Cancellation))
			.ShouldBe(ErrorCategory.Indeterminate);
	}

	[Fact]
	async Task SetPhoneNumberAsync_maps_the_IdentityResult_an_indeterminate_write_and_an_erased_user()
	{
		NorseUser user = new();
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.SetPhoneNumberAsync(user, "+15551234567").Returns(IdentityResult.Success);
		_userManager.SetPhoneNumberAsync(user, "+15550000001")
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().ConcurrencyFailure()));
		_userManager.SetPhoneNumberAsync(user, "+15550000002")
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));
		_userManager.SetPhoneNumberAsync(user, "+15550000003").ThrowsAsync(new KeyDestroyedException(receipt));

		(await _userManager.Outcome.SetPhoneNumberAsync(user, "+15551234567", Cancellation))
			.TryGetValue(out Success<Unit> _).ShouldBeTrue();
		Category(await _userManager.Outcome.SetPhoneNumberAsync(user, "+15550000001", Cancellation))
			.ShouldBe(ErrorCategory.Conflict);
		Category(await _userManager.Outcome.SetPhoneNumberAsync(user, "+15550000002", Cancellation))
			.ShouldBe(ErrorCategory.Indeterminate);
		(await _userManager.Outcome.SetPhoneNumberAsync(user, "+15550000003", Cancellation))
			.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Erased);
		failed.Problem.Receipt.ShouldBe(receipt);
	}

	[Fact]
	async Task ChangePasswordAsync_maps_PasswordMismatch_to_InvalidCredentials_an_indeterminate_write_and_an_erased_user()
	{
		NorseUser user = new();
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.ChangePasswordAsync(user, "current", "Strong-1!").Returns(IdentityResult.Success);
		_userManager.ChangePasswordAsync(user, "wrong", "Strong-1!")
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().PasswordMismatch()));
		_userManager.ChangePasswordAsync(user, "unsure", "Strong-1!")
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));
		_userManager.ChangePasswordAsync(user, "erased", "Strong-1!").ThrowsAsync(new KeyDestroyedException(receipt));

		(await _userManager.Outcome.ChangePasswordAsync(user, "current", "Strong-1!", Cancellation))
			.TryGetValue(out Success<Unit> _).ShouldBeTrue();
		Category(await _userManager.Outcome.ChangePasswordAsync(user, "wrong", "Strong-1!", Cancellation))
			.ShouldBe(ErrorCategory.InvalidCredentials);
		Category(await _userManager.Outcome.ChangePasswordAsync(user, "unsure", "Strong-1!", Cancellation))
			.ShouldBe(ErrorCategory.Indeterminate);
		(await _userManager.Outcome.ChangePasswordAsync(user, "erased", "Strong-1!", Cancellation))
			.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Erased);
		failed.Problem.Receipt.ShouldBe(receipt);
	}

	[Fact]
	async Task AddPasswordAsync_maps_UserAlreadyHasPassword_to_Conflict_an_indeterminate_write_and_an_erased_user()
	{
		NorseUser user = new();
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.AddPasswordAsync(user, "Strong-1!").Returns(IdentityResult.Success);
		_userManager.AddPasswordAsync(user, "Already-1!")
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().UserAlreadyHasPassword()));
		_userManager.AddPasswordAsync(user, "Unsure-1!")
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));
		_userManager.AddPasswordAsync(user, "Erased-1!").ThrowsAsync(new KeyDestroyedException(receipt));

		(await _userManager.Outcome.AddPasswordAsync(user, "Strong-1!", Cancellation))
			.TryGetValue(out Success<Unit> _).ShouldBeTrue();
		Category(await _userManager.Outcome.AddPasswordAsync(user, "Already-1!", Cancellation))
			.ShouldBe(ErrorCategory.Conflict);
		Category(await _userManager.Outcome.AddPasswordAsync(user, "Unsure-1!", Cancellation))
			.ShouldBe(ErrorCategory.Indeterminate);
		(await _userManager.Outcome.AddPasswordAsync(user, "Erased-1!", Cancellation))
			.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Erased);
		failed.Problem.Receipt.ShouldBe(receipt);
	}

	[Fact]
	async Task AddLoginAsync_maps_LoginAlreadyAssociated_to_Conflict_an_indeterminate_write_and_an_erased_user()
	{
		NorseUser user = new();
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		UserLoginInfo linked = new("Provider", "linked", "Provider"), taken = new("Provider", "taken", "Provider"),
			unsure = new("Provider", "unsure", "Provider"), erased = new("Provider", "erased", "Provider");
		_userManager.AddLoginAsync(user, linked).Returns(IdentityResult.Success);
		_userManager.AddLoginAsync(user, taken)
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().LoginAlreadyAssociated()));
		_userManager.AddLoginAsync(user, unsure)
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));
		_userManager.AddLoginAsync(user, erased).ThrowsAsync(new KeyDestroyedException(receipt));

		(await _userManager.Outcome.AddLoginAsync(user, linked, Cancellation))
			.TryGetValue(out Success<Unit> _).ShouldBeTrue();
		Category(await _userManager.Outcome.AddLoginAsync(user, taken, Cancellation)).ShouldBe(ErrorCategory.Conflict);
		Category(await _userManager.Outcome.AddLoginAsync(user, unsure, Cancellation))
			.ShouldBe(ErrorCategory.Indeterminate);
		(await _userManager.Outcome.AddLoginAsync(user, erased, Cancellation))
			.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Erased);
		failed.Problem.Receipt.ShouldBe(receipt);
	}

	[Fact]
	async Task RemoveLoginAsync_maps_LastSignInMethod_to_Conflict_an_indeterminate_write_and_an_erased_user()
	{
		NorseUser user = new();
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.RemoveLoginAsync(user, "Provider", "removed").Returns(IdentityResult.Success);
		_userManager.RemoveLoginAsync(user, "Provider", "last")
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.LastSignInMethod }));
		_userManager.RemoveLoginAsync(user, "Provider", "unsure")
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));
		_userManager.RemoveLoginAsync(user, "Provider", "erased").ThrowsAsync(new KeyDestroyedException(receipt));

		(await _userManager.Outcome.RemoveLoginAsync(user, "Provider", "removed", Cancellation))
			.TryGetValue(out Success<Unit> _).ShouldBeTrue();
		Category(await _userManager.Outcome.RemoveLoginAsync(user, "Provider", "last", Cancellation))
			.ShouldBe(ErrorCategory.Conflict);
		Category(await _userManager.Outcome.RemoveLoginAsync(user, "Provider", "unsure", Cancellation))
			.ShouldBe(ErrorCategory.Indeterminate);
		(await _userManager.Outcome.RemoveLoginAsync(user, "Provider", "erased", Cancellation))
			.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Erased);
		failed.Problem.Receipt.ShouldBe(receipt);
	}

	[Fact]
	async Task ReplaceRecoveryCodesAsync_throws_loudly_on_a_stock_manager() =>
		await Should.ThrowAsync<InvalidOperationException>(async () =>
			await _userManager.Outcome.ReplaceRecoveryCodesAsync(new(), 10, Cancellation));

	[Fact]
	async Task ReplaceRecoveryCodesAsync_answers_the_codes_and_keeps_an_indeterminate_result()
	{
		var manager = Substitute.For<UserManager<NorseUser>, IRecoveryCodeReplacement>(
			Substitute.For<IUserStore<NorseUser>>(), null!, new PasswordHasher<NorseUser>(),
			Array.Empty<IUserValidator<NorseUser>>(), Array.Empty<IPasswordValidator<NorseUser>>(),
			new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null!,
			NullLogger<UserManager<NorseUser>>.Instance);
		NorseUser replaced = new(), unsure = new();
		string[] codes = ["one", "two", "three"];
		((IRecoveryCodeReplacement)manager).ReplaceRecoveryCodesAsync(replaced, 3)
			.Returns((IdentityResult.Success, codes));
		((IRecoveryCodeReplacement)manager).ReplaceRecoveryCodesAsync(unsure, 3)
			.Returns((IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }), codes));

		(await manager.Outcome.ReplaceRecoveryCodesAsync(replaced, 3, Cancellation))
			.TryGetValue(out Success<string[]> success).ShouldBeTrue();
		success.Value.ShouldBeSameAs(codes);
		var category = Category(await manager.Outcome.ReplaceRecoveryCodesAsync(unsure, 3, Cancellation));
		category.ShouldBe(ErrorCategory.Indeterminate);
		category.ShouldNotBe(ErrorCategory.Fault);
	}

	static ClaimsPrincipal Principal(string id) =>
		new(new ClaimsIdentity([new(ClaimTypes.NameIdentifier, id)], "Test"));

	static ErrorCategory Category<T>(Outcome<T> outcome)
		where T : notnull
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem.Category;
	}
}
