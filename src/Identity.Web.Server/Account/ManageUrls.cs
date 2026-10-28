using Microsoft.AspNetCore.Http.Extensions;

namespace Norse.Identity.Web.Server.Account;

/// <summary>
///     The one builder of status-key URLs: every Manage landing that carries a status key is authored here, server
///     side, root-relative and qualified by the live request's <c>PathBase</c>, so the URL survives non-root hosting.
/// </summary>
static class ManageUrls
{
	/// <summary>Builds <paramref name="route" /> under <paramref name="pathBase" /> with <paramref name="statusKey" /> on <c>?status=</c>.</summary>
	/// <param name="pathBase">The live request's <c>PathBase</c>.</param>
	/// <param name="route">The root-relative Manage route, such as <c>/Account/Manage/Passkeys</c>.</param>
	/// <param name="statusKey">A <c>ManageStatus</c> key.</param>
	/// <returns>The root-relative, PathBase-qualified URL.</returns>
	public static string Status(PathString pathBase, string route, string statusKey) =>
		UriHelper.BuildRelative(pathBase, route, QueryString.Create("status", statusKey));
}
