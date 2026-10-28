using Microsoft.AspNetCore.Http;

namespace Norse.Identity.Web.Server.Tests;

public sealed class AccountLinksTests
{
	static HttpRequest Request()
	{
		DefaultHttpContext context = new();
		context.Request.Scheme = "https";
		context.Request.Host = new("example.test");
		context.Request.PathBase = "/base";
		return context.Request;
	}

	[Fact]
	void The_reset_password_link_is_absolute_and_keeps_the_PathBase() =>
		AccountLinks.ResetPassword(Request(), "the-code")
			.ShouldBe("https://example.test/base/Account/ResetPassword?code=the-code");

	[Fact]
	void The_confirm_email_link_is_absolute_and_keeps_the_PathBase() =>
		AccountLinks.ConfirmEmail(Request(), "the-user", "the-code")
			.ShouldBe("https://example.test/base/Account/ConfirmEmail?userId=the-user&code=the-code");

	[Fact]
	void ConfirmEmailChange_builds_the_absolute_link_with_user_email_and_code() =>
		AccountLinks.ConfirmEmailChange(Request(), "u", "new@example.com", "c")
			.ShouldBe("https://example.test/base/Account/ConfirmEmailChange?userId=u&email=new@example.com&code=c");
}
