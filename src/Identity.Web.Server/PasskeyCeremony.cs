namespace Norse.Identity.Web.Server;

/// <summary>
///     The first half of a passkey ceremony: the WebAuthn options for the browser, and the handler's ceremony state,
///     data-protected and time-limited by <see cref="NorseSignInManager" /> so the server keeps nothing between the two
///     halves. The framework parks that state in the partial two-factor cookie, which cannot be written on a circuit.
/// </summary>
/// <param name="OptionsJson">The WebAuthn options, as JSON for <c>navigator.credentials</c>.</param>
/// <param name="State">The protected ceremony state the client echoes back; opaque to it.</param>
public sealed record PasskeyCeremony(string OptionsJson, string State);
