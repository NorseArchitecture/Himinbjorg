using Microsoft.AspNetCore.Http;
using Norse.AuthN.Components.Shared;
using Norse.Identity.Web.Server.Account;

namespace Norse.Identity.Web.Server.Tests.Account;

/// <summary>
///     <see cref="ManageUrls.Status" /> is the one place a status-key URL is built: root-relative, PathBase-qualified,
///     the key on the <c>status</c> query parameter.
/// </summary>
public sealed class ManageUrlsTests
{
	[Fact]
	void An_empty_PathBase_answers_the_root_relative_route() =>
		ManageUrls.Status(PathString.Empty, "/Account/Manage/TwoFactorAuthentication", ManageStatus.AuthenticatorVerified)
			.ShouldBe("/Account/Manage/TwoFactorAuthentication?status=authenticator-verified");

	[Fact]
	void A_PathBase_qualifies_the_route() =>
		ManageUrls.Status(new("/base"), "/Account/Manage/Passkeys", ManageStatus.PasskeyUpdated)
			.ShouldBe("/base/Account/Manage/Passkeys?status=passkey-updated");
}
