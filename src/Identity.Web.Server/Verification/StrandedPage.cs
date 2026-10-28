namespace Norse.Identity.Web.Server.Verification;

/// <summary>One page of the stranded-account traversal (T3-28).</summary>
/// <param name="Candidates">
///     The page's stranded accounts, in the provider's id order: a first sighting, reported only if the next run's
///     recheck still finds them stranded. Returned whether or not <paramref name="Advanced" />.
/// </param>
/// <param name="NextCursor">
///     Where the traversal resumes: the page's last id, or <see langword="null" /> when this was the last page.
/// </param>
/// <param name="Wrapped">Whether this was the last page, so the cursor went back to the start in the same write.</param>
/// <param name="Advanced">
///     Whether this run's compare-and-set moved the cursor. <see langword="false" /> means another replica advanced
///     first and this run's advance was discarded.
/// </param>
sealed record StrandedPage(Guid[] Candidates, Guid? NextCursor, bool Wrapped, bool Advanced);
