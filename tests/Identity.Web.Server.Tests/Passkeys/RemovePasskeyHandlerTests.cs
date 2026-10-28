using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.Passkeys;

namespace Norse.Identity.Web.Server.Tests.Passkeys;

/// <summary>
///     <see cref="RemovePasskeyHandler" />: removes one of the caller's passkeys in place, answering
///     <c>true</c>. An id that does not decode answers <see cref="ErrorCategory.Validation" /> and a passkey the caller
///     no longer has <see cref="ErrorCategory.NotFound" />, both with nothing written. No last-credential guard: a
///     passkey is never an account's sole credential.
/// </summary>
public sealed class RemovePasskeyHandlerTests
{
	static readonly byte[] _id = [0xFB, 0xFF, 0xBF];

	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly NorseUser _user = new() { Id = Guid.CreateVersion7(), UserName = "user@example.com", Email = "user@example.com" };

	public RemovePasskeyHandlerTests() =>
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user);

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task A_malformed_id_answers_Validation_and_writes_nothing()
	{
		var problem = BaseRequest.ProblemOf(await HandleAsync("not base64url!"));

		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors["CredentialId"].ShouldBe(["The passkey id is not valid."]);
		await _userManager.DidNotReceiveWithAnyArgs().GetPasskeyAsync(default!, default!);
		await _userManager.DidNotReceiveWithAnyArgs().RemovePasskeyAsync(default!, default!);
	}

	[Fact]
	async Task A_removed_passkey_answers_NotFound_and_writes_nothing()
	{
		_userManager.GetPasskeyAsync(_user, Arg.Any<byte[]>()).Returns((UserPasskeyInfo?)null);

		var problem = BaseRequest.ProblemOf(await HandleAsync("-_-_"));

		problem.Category.ShouldBe(ErrorCategory.NotFound);
		problem.Errors.Values.SelectMany(static messages => messages).ShouldBe(["The passkey was not found."]);
		await _userManager.DidNotReceiveWithAnyArgs().RemovePasskeyAsync(default!, default!);
	}

	[Fact]
	async Task Remove_removes()
	{
		_userManager.GetPasskeyAsync(_user, Arg.Is<byte[]>(id => id.SequenceEqual(_id))).Returns(TestPasskeys.Info(_id));
		_userManager.RemovePasskeyAsync(_user, Arg.Any<byte[]>()).Returns(IdentityResult.Success);

		BaseRequest.ValueOf(await HandleAsync("-_-_")).Value.ShouldBeTrue();
		await _userManager.Received(1).RemovePasskeyAsync(_user, Arg.Is<byte[]>(id => id.SequenceEqual(_id)));
	}

	[Fact]
	async Task A_failed_removal_passes_through()
	{
		_userManager.GetPasskeyAsync(_user, Arg.Any<byte[]>()).Returns(TestPasskeys.Info(_id));
		_userManager.RemovePasskeyAsync(_user, Arg.Any<byte[]>())
			.Returns(IdentityResult.Failed(new IdentityError { Code = NorseIdentityErrorCodes.IndeterminateOutcome }));

		BaseRequest.ProblemOf(await HandleAsync("-_-_")).Category.ShouldBe(ErrorCategory.Indeterminate);
	}

	[Fact]
	async Task An_erased_subject_answers_Erased()
	{
		ErasureReceipt receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).ThrowsAsync(new KeyDestroyedException(receipt));

		var problem = BaseRequest.ProblemOf(await HandleAsync("-_-_"));

		problem.Category.ShouldBe(ErrorCategory.Erased);
		problem.Receipt.ShouldBeSameAs(receipt);
		await _userManager.DidNotReceiveWithAnyArgs().RemovePasskeyAsync(default!, default!);
	}

	ValueTask<Outcome<BoolResponse>> HandleAsync(string credentialId)
	{
		RemovePasskeyHandler handler = new(new AccountCaller(FakePrincipal.For(_user.Id), _userManager), _userManager);
		return handler.Handle(new(new RemovePasskeyRequest { CredentialId = credentialId }), Cancellation);
	}
}
