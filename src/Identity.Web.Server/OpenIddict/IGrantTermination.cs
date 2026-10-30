namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     <c>EndGrant(authorizationId)</c> (2026-10-29 OpenIddict spec §5.5): the one procedure every path that ends a grant
///     runs. Step 1 revokes the authorization, the durable boundary; step 2 revokes its tokens, only after step 1 is
///     confirmed.
/// </summary>
interface IGrantTermination
{
	/// <summary>Ends the grant <paramref name="authorizationId" /> names.</summary>
	/// <param name="authorizationId">The grant's authorization.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>Whether step 1 was confirmed.</returns>
	Task<GrantEnd> EndAsync(Guid authorizationId, CancellationToken cancellationToken);
}
