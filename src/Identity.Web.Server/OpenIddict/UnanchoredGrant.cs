using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     A code or refresh token that reaches the grant boundary (2026-10-29 OpenIddict spec §5.5) without a token id or an
///     authorization id that parses: fail-closed, its caller refuses it, never passes it through or redeems it unguarded.
///     Every code and refresh token this server issues carries both (§5.2, §4.5), so meeting one is an anomaly; before the
///     refusal, the grant that can still be named ends.
/// </summary>
static class UnanchoredGrant
{
	/// <summary>
	///     Ends the authorization <paramref name="authorizationId" /> names when it parses; otherwise the one the token's own
	///     row links (§4.5: the link is the database's), when <paramref name="tokenId" /> parses and the row has one;
	///     otherwise nothing, since there is no grant to end.
	/// </summary>
	/// <param name="database">The request's identity context.</param>
	/// <param name="termination">Ends the grant.</param>
	/// <param name="tokenId">The presented token's id, as validation resolved it.</param>
	/// <param name="authorizationId">The presented token's authorization id, as validation resolved it.</param>
	/// <param name="cancellationToken">The cancellation token, handed to the grant end; the link read ignores it.</param>
	/// <remarks>
	///     The link read decides whether the grant ends, so it ignores the request's cancellation, as
	///     <see cref="GrantTermination" />'s first step does (M2): a client hanging up must not keep its grant alive.
	/// </remarks>
	public static async Task EndAsync(NorseIdentityDbContext database, IGrantTermination termination, string? tokenId,
		string? authorizationId, CancellationToken cancellationToken)
	{
		if (Guid.TryParse(authorizationId, out var authorization))
		{
			await termination.EndAsync(authorization, cancellationToken).ConfigureAwait(false);
			return;
		}

		if (!Guid.TryParse(tokenId, out var token))
			return;

		var linked = await database.Set<NorseOpenIddictToken>()
			.Where(entry => entry.Id == token)
			.Select(static entry => entry.AuthorizationId)
			.SingleOrDefaultAsync(CancellationToken.None)
			.ConfigureAwait(false);
		if (linked is { } named)
			await termination.EndAsync(named, cancellationToken).ConfigureAwait(false);
	}
}
