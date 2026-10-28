using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Http.Extensions;

namespace Norse.Identity.Web.Server;

/// <summary>
///     The one decider of a landing (T3-2): a client-supplied <c>returnUrl</c> is honored only when it is
///     unambiguously local and is no external-login route (<see cref="ExternalLoginRoutes" />), and everything else lands on
///     the app root. Hard-fail on ambiguity -- nothing is normalized
///     and then accepted (Buvy r6). The candidate is split at its first literal <c>?</c> or <c>#</c> before any decoding,
///     because decoding first would let <c>%3F</c>/<c>%23</c> become a new boundary that hides part of the path from
///     validation; the separator, encoding, dot-segment and <c>PathBase</c> checks then judge the path alone, while
///     length and control characters are judged over the whole candidate. Query and fragment cannot change the
///     immediate redirect's authority or path (WHATWG URL, path state), so an accepted candidate keeps them verbatim;
///     a destination that later interprets a URL-shaped query value validates it itself.
/// </summary>
static class ReturnUrls
{
	/// <summary>The longest candidate considered; anything longer lands on the app root.</summary>
	public const int MaxLength = 2048;

	/// <summary>
	///     Answers <paramref name="candidate" /> unchanged when it is local to the app under <paramref name="pathBase" />,
	///     otherwise the app root, <c>PathBase</c>-qualified.
	/// </summary>
	/// <param name="candidate">The client-supplied return URL, possibly null or empty.</param>
	/// <param name="pathBase">The live request's <c>PathBase</c>; a set one must contain the landing by segments.</param>
	/// <returns>The landing.</returns>
	public static string Resolve(string? candidate, PathString pathBase) =>
		IsLocal(candidate, pathBase) ?
			candidate :
			UriHelper.BuildRelative(pathBase, "/");

	static bool IsLocal([NotNullWhen(true)] string? candidate, PathString pathBase)
	{
		// 1. Global: length, and control characters anywhere -- path, query or fragment -- raw or decoded once.
		if (string.IsNullOrEmpty(candidate) || candidate.Length > MaxLength
			|| HasControl(candidate) || HasControl(Uri.UnescapeDataString(candidate)))
			return false;

		// 2. Split at the first literal ? or #, before any decoding.
		var boundary = candidate.AsSpan().IndexOfAny('?', '#');
		var path = boundary < 0 ?
			candidate :
			candidate[..boundary];

		// 3. The path only, raw and decoded exactly once, and never re-split at a decoded ? or #.
		if (!path.StartsWith('/'))
			return false;
		var decodedPath = Uri.UnescapeDataString(path);
		if (IsAmbiguous(path) || IsAmbiguous(decodedPath))
			return false;
		// A decoded ? or # stays inside its segment, so /app/x%3F/../../outside still shows its .. segments.
		foreach (var segment in decodedPath.Split('/'))
			if (segment is "." or "..")
				return false;

		// 4. Containment, on what survived: a set PathBase must prefix the path by whole segments.
		if (pathBase.HasValue)
		{
			var root = pathBase.Value!;
			if (!path.StartsWith(root, StringComparison.Ordinal)
				|| (path.Length != root.Length && path[root.Length] != '/'))
				return false;
		}

		// 5. Never an external-login route, raw or decoded: every continuation navigates to its landing same-origin, so
		// a landing that is a start would carry a cross-site start past the Fetch-Metadata check (T3-34).
		return !ExternalLoginRoutes.IsExternalLoginRoute(path, pathBase)
			&& !ExternalLoginRoutes.IsExternalLoginRoute(decodedPath, pathBase);
	}

	static bool HasControl(string value)
	{
		foreach (var character in value)
			if (char.IsControl(character))
				return true;
		return false;
	}

	// A backslash or an empty segment reads as an authority to some resolvers; an encoded dot, slash or backslash
	// survives one decode as a second-pass separator or dot segment -- so %252e is caught after the one decode.
	static bool IsAmbiguous(string path) =>
		path.Contains('\\', StringComparison.Ordinal)
		|| path.Contains("//", StringComparison.Ordinal)
		|| path.Contains("%2e", StringComparison.OrdinalIgnoreCase)
		|| path.Contains("%2f", StringComparison.OrdinalIgnoreCase)
		|| path.Contains("%5c", StringComparison.OrdinalIgnoreCase);
}
