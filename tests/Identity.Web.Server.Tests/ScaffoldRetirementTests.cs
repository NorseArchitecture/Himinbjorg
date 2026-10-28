using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Http;

namespace Norse.Identity.Web.Server.Tests;

public sealed class ScaffoldRetirementTests
{
	[Fact]
	void The_retired_scaffold_routes_no_longer_exist_in_this_assembly()
	{
		string[] retired = ["/Account/ForgotPassword", "/Account/ResetPassword", "/Account/LoginWith2fa", "/Account/LoginWithRecoveryCode", "/Account/ConfirmEmail", "/Account/ConfirmEmailChange", "/Account/ResendEmailConfirmation", "/Account/RegisterConfirmation", "/Account/InvalidUser", "/Account/Manage", "/Account/Manage/Email", "/Account/Manage/ChangePassword", "/Account/Manage/SetPassword", "/Account/Manage/ExternalLogins", "/Account/Manage/DeletePersonalData"];
		var routes = typeof(LoginHandler).Assembly.GetTypes()
			.SelectMany(t => t.GetCustomAttributes<RouteAttribute>())
			.Select(r => r.Template);
		routes.ShouldNotContain(template => retired.Contains(template, StringComparer.OrdinalIgnoreCase));
	}

	[Fact]
	void RedirectToInvalidUser_sends_the_stale_session_to_heimdalls_logout_page()
	{
		RecordingNavigationManager navigation = new();
		DefaultHttpContext context = new() { User = new(new ClaimsIdentity("Test")) };
		using var userManager = MockUserManager.Create();
		userManager.GetUserId(context.User).Returns("the-user");

		new IdentityRedirectManager(navigation).RedirectToInvalidUser(userManager, context);

		navigation.NavigatedTo.ShouldBe("Account/Logout");
		var cookie = context.Response.Headers.SetCookie.ToString();
		cookie.ShouldContain(IdentityRedirectManager.StatusCookieName);
		cookie.ShouldContain(Uri.EscapeDataString("Error: Unable to load user with ID 'the-user'."));
	}

	/// <summary>A <see cref="NavigationManager" /> that records the last navigation instead of performing it.</summary>
	sealed class RecordingNavigationManager : NavigationManager
	{
		public RecordingNavigationManager() =>
			Initialize("https://example.test/", "https://example.test/Account/Manage");

		public string? NavigatedTo { get; private set; }

		protected override void NavigateToCore(string uri, NavigationOptions options) =>
			NavigatedTo = uri;
	}
}
