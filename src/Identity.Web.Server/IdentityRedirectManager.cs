using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Identity;

namespace Norse.Identity.Web.Server;

/// <summary>Handles safe navigation and status-message-cookie redirects for the Identity Razor components.</summary>
/// <param name="navigationManager">The navigation manager used to compute and perform redirects.</param>
public sealed class IdentityRedirectManager(NavigationManager navigationManager)
{
	/// <summary>The name of the cookie used to carry a one-time status message across a redirect.</summary>
	public const string StatusCookieName = "Identity.StatusMessage";

	static readonly CookieBuilder _statusCookieBuilder = new()
	{
		SameSite = SameSiteMode.Strict,
		HttpOnly = true,
		IsEssential = true,
		MaxAge = TimeSpan.FromSeconds(5),
	};

	/// <summary>
	/// Navigates to <paramref name="uri"/>, coercing it to a base-relative path first if it is
	/// absolute so a caller-supplied value can never be used as an open redirect.
	/// </summary>
	/// <param name="uri">The destination URI, or <see langword="null"/> to redirect to the app root.</param>
	public void RedirectTo(string? uri)
	{
		uri ??= "";

		// Prevent open redirects.
		if (!Uri.IsWellFormedUriString(uri, UriKind.Relative))
		{
			uri = navigationManager.ToBaseRelativePath(uri);
		}

		navigationManager.NavigateTo(uri);
	}

	/// <summary>
	/// Navigates to <paramref name="uri"/> with the given query string parameters appended.
	/// </summary>
	/// <param name="uri">The destination URI, without query parameters.</param>
	/// <param name="queryParameters">The query parameters to append to <paramref name="uri"/>.</param>
	public void RedirectTo(string uri, Dictionary<string, object?> queryParameters)
	{
		var uriWithoutQuery = navigationManager.ToAbsoluteUri(uri).GetLeftPart(UriPartial.Path);
		var newUri = navigationManager.GetUriWithQueryParameters(uriWithoutQuery, queryParameters);
		RedirectTo(newUri);
	}

	/// <summary>
	/// Stores <paramref name="message"/> in the status-message cookie and redirects to <paramref name="uri"/>
	/// so it can be read and displayed after the next page load.
	/// </summary>
	/// <param name="uri">The destination URI.</param>
	/// <param name="message">The status message to surface on the destination page.</param>
	/// <param name="context">The current HTTP context, used to write the status cookie.</param>
	public void RedirectToWithStatus(string uri, string message, HttpContext context)
	{
		context.Response.Cookies.Append(StatusCookieName, message, _statusCookieBuilder.Build(context));
		RedirectTo(uri);
	}

	string CurrentPath =>
		navigationManager.ToAbsoluteUri(navigationManager.Uri).GetLeftPart(UriPartial.Path);

	/// <summary>
	/// Re-navigates to the current page, forcing Blazor to reload it.
	/// </summary>
	public void RedirectToCurrentPage() => RedirectTo(CurrentPath);

	/// <summary>
	/// Stores <paramref name="message"/> in the status-message cookie and re-navigates to the current page.
	/// </summary>
	/// <param name="message">The status message to surface after the reload.</param>
	/// <param name="context">The current HTTP context, used to write the status cookie.</param>
	public void RedirectToCurrentPageWithStatus(string message, HttpContext context) =>
		RedirectToWithStatus(CurrentPath, message, context);

	/// <summary>
	/// Redirects to the invalid-user page with a status message identifying the missing user ID.
	/// </summary>
	/// <param name="userManager">The user manager used to resolve the current user's ID for the message.</param>
	/// <param name="context">The current HTTP context, used to read the user principal and write the status cookie.</param>
	public void RedirectToInvalidUser(UserManager<NorseUser> userManager, HttpContext context) =>
		RedirectToWithStatus("Account/InvalidUser", $"Error: Unable to load user with ID '{userManager.GetUserId(context.User)}'.", context);
}
