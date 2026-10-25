namespace Norse.Identity.Outcomes;

/// <summary>
///     A write whose commit may or may not have taken effect (2026-10-24 explicit-writes spec §4.10): the commit failed
///     after it was issued, so the database may hold the change though its acknowledgement was lost. Nothing retries
///     it. The caller re-reads and decides; an immediate operation (the access-failed increment, a recovery-code
///     redemption) is never repeated, and sign-in fails closed.
/// </summary>
/// <remarks>
///     It exists only to carry that state across <c>UserManager</c>'s plumbing, out of the store's fixed-signature
///     methods that return a count or a flag (spec §4.12); <see cref="IdentityOutcomeMap" /> maps it to
///     <c>ErrorCategory.Indeterminate</c>. Public because the store that throws it (<c>Identity.Web.Server</c>) and
///     the map that classifies it live in different assemblies.
/// </remarks>
/// <param name="message">What was being committed.</param>
/// <param name="innerException">The failure the commit answered.</param>
public sealed class IndeterminateWriteException(string message, Exception innerException) :
	Exception(message, innerException);
