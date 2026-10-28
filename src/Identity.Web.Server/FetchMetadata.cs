namespace Norse.Identity.Web.Server;

/// <summary>
///     The fail-closed Fetch-Metadata check the antiforgery-free external-login starts stand on (T3-34): a start
///     proceeds only when the browser says the request came from this origin or from the user (a typed URL, a
///     bookmark). An absent header, a repeated one, or any other value is refused, so a browser that does not send
///     Fetch Metadata cannot be driven into a provider challenge by another site.
/// </summary>
static class FetchMetadata
{
	const string SecFetchSite = "Sec-Fetch-Site";

	/// <summary>Whether <paramref name="request" /> carries exactly one <c>Sec-Fetch-Site</c> of <c>same-origin</c> or <c>none</c>.</summary>
	/// <param name="request">The live request.</param>
	public static bool IsSameOriginOrUserInitiated(HttpRequest request)
	{
		ArgumentNullException.ThrowIfNull(request);
		if (!request.Headers.TryGetValue(SecFetchSite, out var values) || values.Count != 1)
			return false;
		var value = values[0];
		return string.Equals(value, "same-origin", StringComparison.OrdinalIgnoreCase)
			|| string.Equals(value, "none", StringComparison.OrdinalIgnoreCase);
	}
}
