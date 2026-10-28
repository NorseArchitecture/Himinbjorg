using System.Reflection;
using Microsoft.AspNetCore.Components;
using Norse.Identity.Web.Server.ExternalLogin;

namespace Norse.Identity.Web.Server.Tests;

public sealed class ScaffoldRetirementTests
{
	[Fact]
	void The_retired_scaffold_routes_no_longer_exist_in_this_assembly()
	{
		string[] retired = ["/Account/ForgotPassword", "/Account/ResetPassword", "/Account/LoginWith2fa", "/Account/LoginWithRecoveryCode", "/Account/ConfirmEmail", "/Account/ConfirmEmailChange", "/Account/ResendEmailConfirmation", "/Account/RegisterConfirmation", "/Account/InvalidUser", "/Account/Manage", "/Account/Manage/Email", "/Account/Manage/ChangePassword", "/Account/Manage/SetPassword", "/Account/Manage/ExternalLogins", "/Account/Manage/DeletePersonalData", "/Account/Manage/TwoFactorAuthentication", "/Account/Manage/EnableAuthenticator", "/Account/Manage/ResetAuthenticator", "/Account/Manage/Disable2fa", "/Account/Manage/GenerateRecoveryCodes", "/Account/Manage/Passkeys", "/Account/Manage/RenamePasskey/{Id}"];
		var routes = typeof(LoginHandler).Assembly.GetTypes()
			.SelectMany(t => t.GetCustomAttributes<RouteAttribute>())
			.Select(r => r.Template);
		routes.ShouldNotContain(template => retired.Contains(template, StringComparer.OrdinalIgnoreCase));
	}

	/// <summary>
	///     The duplicate-route hazard (§8): Heimdall serves every Account page, so the one page this assembly still
	///     routes is the external-login callback, which needs the provider's round trip and the sign-in manager.
	/// </summary>
	[Fact]
	void The_only_routable_component_is_the_external_login_callback()
	{
		var routable = typeof(LoginHandler).Assembly.GetTypes()
			.SelectMany(static type => type.GetCustomAttributes<RouteAttribute>().Select(route => (type, route.Template)));

		routable.ShouldHaveSingleItem().ShouldBe((typeof(ExternalLoginCallback), "/Account/ExternalLogin"));
	}
}
