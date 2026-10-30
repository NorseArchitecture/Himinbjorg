namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     The <c>norse_reauth</c> marker an authorize challenge carries (2026-10-29 OpenIddict spec §5.2): proof, once a
///     credential sign-in landing on it stamps its id onto the cookie, that the credential was presented after the
///     challenge and for this transaction. Travels only protected (<see cref="ReauthMarkers" />).
/// </summary>
/// <param name="MarkerId">The random 128-bit id the bound cookie carries as <c>norse_reauth</c>.</param>
/// <param name="UserId">
///     The user the challenge was issued to; <see langword="null" /> for an anonymous challenge, which binds whoever
///     presents the credential.
/// </param>
/// <param name="TransactionHash">The SHA-256 of the canonical authorize transaction (<see cref="AuthorizeTransaction" />).</param>
/// <param name="ExpiresAt">When the marker stops unprotecting.</param>
sealed record ReauthMarker(Guid MarkerId, Guid? UserId, byte[] TransactionHash, DateTimeOffset ExpiresAt);
