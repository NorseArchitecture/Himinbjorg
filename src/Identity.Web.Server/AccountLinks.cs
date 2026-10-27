using Microsoft.AspNetCore.Http.Extensions;

namespace Norse.Identity.Web.Server;

/// <summary>
///     The absolute links the account emails carry, built from the live request so they keep its scheme, host and
///     <c>PathBase</c>. Unencoded for HTML: no body is composed here, so encoding is an HTML sender's job.
/// </summary>
static class AccountLinks
{
	/// <summary>The password-reset link: <c>/Account/ResetPassword?code=…</c>.</summary>
	/// <param name="request">The live request.</param>
	/// <param name="code">The Base64Url-encoded reset token.</param>
	/// <returns>The absolute link.</returns>
	public static string ResetPassword(HttpRequest request, string code) =>
		UriHelper.BuildAbsolute(request.Scheme, request.Host, request.PathBase, "/Account/ResetPassword",
			QueryString.Create("code", code));

	/// <summary>The email-confirmation link: <c>/Account/ConfirmEmail?userId=…&amp;code=…</c>.</summary>
	/// <param name="request">The live request.</param>
	/// <param name="userId">The user's id.</param>
	/// <param name="code">The Base64Url-encoded confirmation token.</param>
	/// <returns>The absolute link.</returns>
	public static string ConfirmEmail(HttpRequest request, string userId, string code) =>
		UriHelper.BuildAbsolute(request.Scheme, request.Host, request.PathBase, "/Account/ConfirmEmail",
			QueryString.Create("userId", userId).Add("code", code));
}
