using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.Account;
using Norse.Identity.Web.Server.Passkeys;

namespace Norse.Identity.Web.Server.Tests.Passkeys;

/// <summary>
///     <see cref="GetPasskeysHandler" />: the caller's passkeys, each id base64url-encoded, an unnamed passkey named
///     <c>""</c>, and each rename URL authored here under the live <c>PathBase</c>.
/// </summary>
public sealed class GetPasskeysHandlerTests
{
	readonly UserManager<NorseUser> _userManager = MockUserManager.Create();
	readonly NorseUser _user = new() { Id = Guid.CreateVersion7(), UserName = "user@example.com", Email = "user@example.com" };

	public GetPasskeysHandlerTests() =>
		_userManager.GetUserAsync(Arg.Any<ClaimsPrincipal>()).Returns(_user);

	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Each_passkey_answers_its_base64url_id_its_name_and_a_PathBase_rename_url()
	{
		_userManager.GetPasskeysAsync(_user).Returns([
			TestPasskeys.Info([0xFB, 0xFF, 0xBF], "Laptop"),
			TestPasskeys.Info([0x01, 0x02, 0x03])
		]);

		var passkeys = BaseRequest.ValueOf(await HandleAsync()).Passkeys;

		passkeys.ShouldBe([
			new PasskeyEntry
			{
				CredentialId = "-_-_",
				Name = "Laptop",
				RenameUrl = "/base/Account/Manage/RenamePasskey/-_-_"
			},
			new PasskeyEntry
			{
				CredentialId = "AQID",
				Name = "",
				RenameUrl = "/base/Account/Manage/RenamePasskey/AQID"
			}
		]);
	}

	[Fact]
	async Task No_passkeys_answers_an_empty_list()
	{
		_userManager.GetPasskeysAsync(_user).Returns([]);

		BaseRequest.ValueOf(await HandleAsync()).Passkeys.ShouldBeEmpty();
	}

	ValueTask<Outcome<PasskeysResponse>> HandleAsync()
	{
		GetPasskeysHandler handler = new(new AccountCaller(FakePrincipal.For(_user.Id), _userManager), _userManager,
			BaseRequest.Accessor());
		return handler.Handle(new(Unit.Value), Cancellation);
	}
}
