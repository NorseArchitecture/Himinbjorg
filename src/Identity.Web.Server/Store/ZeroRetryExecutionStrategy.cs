using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Norse.Identity.Web.Server.Store;

/// <summary>
///     A strategy that never retries, under which the store's own transactions run (spec §4.3: blind replay is
///     what duplicates child inserts and increments), and the grant statements too (2026-10-29 OpenIddict spec §5.5:
///     a blind retry of a committed redemption returns zero rows and would misread the server's own write as reuse).
///     EF's <see cref="NonRetryingExecutionStrategy" /> can't serve: it never sets <see cref="ExecutionStrategy.Current" />,
///     so the context's configured retrying strategy still refuses the user-initiated transaction (PoC G1). Any
///     <see cref="ExecutionStrategy" /> does set it, and the configured strategy then passes through; at zero retries
///     this one runs the operation exactly once and rethrows its failure unwrapped, on every provider.
/// </summary>
/// <param name="context">The context whose operations run under it.</param>
sealed class ZeroRetryExecutionStrategy(DbContext context) : ExecutionStrategy(context, 0, TimeSpan.Zero)
{
	/// <inheritdoc />
	protected override bool ShouldRetryOn(Exception exception) =>
		false;
}
