using Microsoft.EntityFrameworkCore;
using Norse.Identity.Web.Server.Store;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     The grant boundary's two statements (2026-10-29 OpenIddict spec §5.5), spelled per provider by
///     <see cref="ProviderStatements" /> and each run exactly once, under <see cref="ZeroRetryExecutionStrategy" />, never
///     the context's retrying strategy. A blind retry of a committed redemption returns zero rows and would misread the
///     server's own write as reuse; the authorization's revocation is retried, but by <c>EndGrant</c>'s own counted
///     attempts, never underneath them.
/// </summary>
static class GrantStatements
{
	/// <summary>
	///     The guarded redemption: one row when the token was <c>valid</c>, bound to <paramref name="authorization" />,
	///     that authorization was <c>valid</c>, and this call alone moved the token to <c>redeemed</c>; zero rows otherwise,
	///     which is reuse.
	/// </summary>
	/// <param name="context">The context.</param>
	/// <param name="token">The presented code or refresh token.</param>
	/// <param name="authorization">The authorization the presented token carries.</param>
	/// <param name="now">The redemption time.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>The number of rows redeemed.</returns>
	public static Task<int> RedeemAsync(DbContext context, Guid token, Guid authorization, DateTimeOffset now,
		CancellationToken cancellationToken = default) =>
		new ZeroRetryExecutionStrategy(context).ExecuteAsync((token, authorization, now),
			(state, cancellation) => ProviderStatements.RedeemGrantTokenAsync(context, state.token, state.authorization,
				state.now, cancellation),
			cancellationToken);

	/// <summary>
	///     <c>EndGrant</c>'s step 1: <c>UPDATE authorizations SET status = 'revoked', concurrency_token = @fresh WHERE id =
	///     @authorization AND status = 'valid'</c>. Zero rows for an authorization already revoked is still success.
	/// </summary>
	/// <param name="context">The context.</param>
	/// <param name="authorization">The authorization.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>The number of rows revoked.</returns>
	public static Task<int> RevokeAuthorizationAsync(DbContext context, Guid authorization,
		CancellationToken cancellationToken = default) =>
		new ZeroRetryExecutionStrategy(context).ExecuteAsync(authorization,
			(id, cancellation) => ProviderStatements.RevokeAuthorizationAsync(context, id, cancellation),
			cancellationToken);
}
