using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.TwoFactor;

namespace Norse.Identity.Web.Server.Tests.TwoFactor;

/// <summary>
///     <see cref="RevealRecoveryCodesHandler" />: a handoff reveals its codes only for the user it was sealed for, under
///     the stamp it was sealed with, while the stored set is still exactly its codes, and only once (M10). Every
///     refusal is one static message and consumes nothing; the one-shot ledger is asked last, with the raw payload and
///     the handoff's own expiry (P5).
/// </summary>
public sealed class RevealRecoveryCodesHandlerTests
{
	const string Stamp = "stamp-1";

	static readonly string[] _codes = ["aaaaa-11111", "bbbbb-22222", "ccccc-33333"];

	readonly EphemeralDataProtectionProvider _dataProtection = new();
	readonly InMemoryPasskeyChallengeLedger _ledger = new();
	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly NorseUser _user = new() { Id = Guid.CreateVersion7(), UserName = "user@example.com", Email = "user@example.com" };

	public RevealRecoveryCodesHandlerTests()
	{
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user);
		_userManager.GetUserIdAsync(_user).Returns(_user.Id.ToString());
		_userManager.GetSecurityStampAsync(_user).Returns(Stamp);
		StoredSetIs(string.Join(';', _codes));
	}

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task A_handoff_reveals_its_codes_and_consumes_its_raw_payload_until_its_own_expiry()
	{
		var handoff = Seal(_user.Id.ToString(), Stamp, _codes);
		RecoveryCodesHandoff.TryUnprotect(Protector(), handoff, out var opened).ShouldBeTrue();

		BaseRequest.ValueOf(await HandleAsync(handoff)).RecoveryCodes.ShouldBe(_codes);

		var (state, expiresAt) = _ledger.Requests.ShouldHaveSingleItem();
		Encoding.UTF8.GetString(state).ShouldBe($"v1|{_user.Id}|{Stamp}|{string.Join(';', _codes)}");
		expiresAt.ShouldBe(opened.ExpiresAt);
	}

	[Fact]
	async Task A_second_reveal_of_the_same_handoff_answers_already_shown()
	{
		var handoff = Seal(_user.Id.ToString(), Stamp, _codes);
		BaseRequest.ValueOf(await HandleAsync(handoff)).RecoveryCodes.ShouldBe(_codes);

		var problem = BaseRequest.ProblemOf(await HandleAsync(handoff));

		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors[string.Empty].ShouldBe(["These recovery codes have already been shown."]);
	}

	[Fact]
	async Task A_bad_handoff_answers_Validation() =>
		await ShouldBeUnavailableAsync("not a handoff!");

	[Fact]
	async Task A_handoff_for_another_user_answers_Validation() =>
		await ShouldBeUnavailableAsync(Seal(Guid.CreateVersion7().ToString(), Stamp, _codes));

	[Fact]
	async Task A_handoff_after_a_stamp_rotation_answers_Validation()
	{
		var handoff = Seal(_user.Id.ToString(), Stamp, _codes);
		_userManager.GetSecurityStampAsync(_user).Returns("stamp-2");

		await ShouldBeUnavailableAsync(handoff);
	}

	[Fact]
	async Task A_handoff_whose_codes_were_replaced_answers_Validation()
	{
		var handoff = Seal(_user.Id.ToString(), Stamp, _codes);
		StoredSetIs("ddddd-44444;eeeee-55555");

		await ShouldBeUnavailableAsync(handoff);
	}

	[Fact]
	async Task A_handoff_after_a_redeemed_code_answers_Validation()
	{
		var handoff = Seal(_user.Id.ToString(), Stamp, _codes);
		StoredSetIs(string.Join(';', _codes[1..]));

		await ShouldBeUnavailableAsync(handoff);
	}

	[Fact]
	async Task A_handoff_with_no_stored_set_answers_Validation()
	{
		var handoff = Seal(_user.Id.ToString(), Stamp, _codes);
		StoredSetIs(null);

		await ShouldBeUnavailableAsync(handoff);
	}

	[Fact]
	async Task An_erased_subject_answers_Erased()
	{
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).ThrowsAsync(new KeyDestroyedException(receipt));

		var problem = BaseRequest.ProblemOf(await HandleAsync(Seal(_user.Id.ToString(), Stamp, _codes)));

		problem.Category.ShouldBe(ErrorCategory.Erased);
		problem.Receipt.ShouldBeSameAs(receipt);
		_ledger.Requests.ShouldBeEmpty();
	}

	async Task ShouldBeUnavailableAsync(string handoff)
	{
		var problem = BaseRequest.ProblemOf(await HandleAsync(handoff));

		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors[string.Empty].ShouldBe(["These recovery codes are no longer available."]);
		_ledger.Requests.ShouldBeEmpty("a refused handoff is not spent");
	}

	void StoredSetIs(string? stored) =>
		_userManager.GetAuthenticationTokenAsync(_user, "[AspNetUserStore]", "RecoveryCodes").Returns(stored);

	string Seal(string userId, string stamp, string[] codes) =>
		RecoveryCodesHandoff.Protect(Protector(), userId, stamp, codes);

	ITimeLimitedDataProtector Protector() =>
		_dataProtection.CreateProtector(RecoveryCodesHandoff.Purpose).ToTimeLimitedDataProtector();

	ValueTask<Outcome<RecoveryCodesResponse>> HandleAsync(string handoff)
	{
		RevealRecoveryCodesHandler handler = new(new AccountCaller(FakePrincipal.For(_user.Id), _userManager), _userManager,
			_dataProtection, _ledger);
		return handler.Handle(new(new() { Handoff = handoff }), Cancellation);
	}
}
