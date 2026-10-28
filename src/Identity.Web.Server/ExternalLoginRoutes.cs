using System.Collections.Immutable;

namespace Norse.Identity.Web.Server;

/// <summary>
///     The external-login HTTP routes: the one set <c>MapNorseExternalLoginEndpoints</c> maps and
///     <see cref="ReturnUrls" /> refuses as a landing. A post-sign-in continuation navigates to its landing from a
///     same-origin document, so a landing that is itself a start would launder a cross-site start past the Fetch-Metadata
///     check (T3-34).
/// </summary>
static class ExternalLoginRoutes
{
	/// <summary>The external sign-in start.</summary>
	public const string Start = "/Account/PerformExternalLogin";

	/// <summary>The link start.</summary>
	public const string LinkStart = "/Account/Manage/LinkExternalLogin";

	/// <summary>The link callback.</summary>
	public const string LinkCallback = "/Account/Manage/LinkExternalLoginCallback";

	/// <summary>Every route above; immutable, since <see cref="ReturnUrls" /> refuses each one as a landing.</summary>
	public static readonly ImmutableArray<string> All = [Start, LinkStart, LinkCallback];

	/// <summary>
	///     Whether <paramref name="path" />, below <paramref name="pathBase" />, is one of <see cref="All" />: case-insensitive,
	///     as routing matches, and with a trailing slash tolerated.
	/// </summary>
	/// <param name="path">A path with no query or fragment.</param>
	/// <param name="pathBase">The live request's <c>PathBase</c>.</param>
	public static bool IsExternalLoginRoute(string path, PathString pathBase)
	{
		if (pathBase.HasValue)
		{
			if (!path.StartsWith(pathBase.Value!, StringComparison.OrdinalIgnoreCase))
				return false;
			path = path[pathBase.Value!.Length..];
		}

		var route = path.EndsWith('/') ?
			path[..^1] :
			path;
		foreach (var candidate in All)
			if (string.Equals(route, candidate, StringComparison.OrdinalIgnoreCase))
				return true;
		return false;
	}
}
