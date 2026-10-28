using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.Passkeys;

namespace Norse.Identity.Web.Server.Tests.Passkeys;

/// <summary>
///     <see cref="GetPasskeyHandler" />: one of the caller's passkeys, the rename page's pre-fill. A passkey the caller
///     does not have answers <see cref="ErrorCategory.NotFound" />, and an id that does not decode
///     <see cref="ErrorCategory.Validation" /> before anything is read.
/// </summary>
public sealed class GetPasskeyHandlerTests
{
	static readonly byte[] _id = [0xFB, 0xFF, 0xBF];

	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly NorseUser _user = new() { Id = Guid.CreateVersion7(), UserName = "user@example.com", Email = "user@example.com" };

	public GetPasskeyHandlerTests() =>
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user);

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task A_found_passkey_answers_its_entry()
	{
		_userManager.GetPasskeyAsync(_user, Arg.Is<byte[]>(id => id.SequenceEqual(_id)))
			.Returns(TestPasskeys.Info(_id, "Laptop"));

		BaseRequest.ValueOf(await HandleAsync("-_-_")).ShouldBe(new PasskeyEntry
		{
			CredentialId = "-_-_",
			Name = "Laptop",
			RenameUrl = "/base/Account/Manage/RenamePasskey/-_-_"
		});
	}

	[Fact]
	async Task A_passkey_the_caller_does_not_have_answers_NotFound()
	{
		_userManager.GetPasskeyAsync(_user, Arg.Any<byte[]>()).Returns((UserPasskeyInfo?)null);

		var problem = BaseRequest.ProblemOf(await HandleAsync("-_-_"));

		problem.Category.ShouldBe(ErrorCategory.NotFound);
		problem.Errors.Values.SelectMany(static messages => messages).ShouldBe(["The passkey was not found."]);
	}

	[Fact]
	async Task A_malformed_id_answers_Validation_and_reads_nothing()
	{
		var problem = BaseRequest.ProblemOf(await HandleAsync("not base64url!"));

		problem.Category.ShouldBe(ErrorCategory.Validation);
		problem.Errors["CredentialId"].ShouldBe(["The passkey id is not valid."]);
		await _userManager.DidNotReceiveWithAnyArgs().GetPasskeyAsync(default!, default!);
	}

	ValueTask<Outcome<PasskeyEntry>> HandleAsync(string credentialId)
	{
		GetPasskeyHandler handler = new(new AccountCaller(FakePrincipal.For(_user.Id), _userManager), _userManager,
			BaseRequest.Accessor());
		return handler.Handle(new(new GetPasskeyRequest { CredentialId = credentialId }), Cancellation);
	}
}
