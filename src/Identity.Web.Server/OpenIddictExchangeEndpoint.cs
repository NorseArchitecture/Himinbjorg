using System.Security.Claims;
using Microsoft.AspNetCore; // OpenIddictServerAspNetCoreHelpers.GetOpenIddictServerRequest lives here, not OpenIddict.Server.AspNetCore.
using Norse.Abstractions.Contracts;
using Norse.Identity.Outcomes;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Norse.Identity.Web.Server;

/// <summary>
///     Mints the token for the client_credentials grant (Himinbjorg#49). OpenIddict has already
///     authenticated the client against the seeded application before this runs (confidential clients
///     require client authentication by default) and has already rejected any grant type other than
///     client_credentials, since only <c>AllowClientCredentialsFlow()</c> is enabled — there is no other
///     flow for a request to arrive as. This handler's job is exactly one thing: build the principal
///     OpenIddict does not invent on its own. It also stamps a <see cref="ClaimTypes.NameIdentifier" />
///     claim carrying the seeded <c>NorseOpenIddictApplication</c>'s own <see cref="Guid" /> id — Midgard's
///     <c>PrincipalAccessor.Seed</c> (the 2026-08-21 principal-at-the-door design) unconditionally requires
///     every principal reaching the mediator, browser or machine lane alike, to carry a GUID-parseable
///     <see cref="ClaimTypes.NameIdentifier" /> claim.
/// </summary>
static class OpenIddictExchangeEndpoint
{
	internal static async Task<IResult> Handle(HttpContext context, IOpenIddictApplicationManager manager)
	{
		var request = context.GetOpenIddictServerRequest() ??
			throw new InvalidOperationException("The OpenIddict request cannot be retrieved.");

		// Internal invariant, not a user-facing branch: a violation here means the flow-gating in
		// AddServer() broke, not that a caller sent a bad request. See OpenIddictExchangeEndpoint's
		// class doc.
		if (!request.IsClientCredentialsGrantType())
			throw new InvalidOperationException(
				$"{nameof(OpenIddictExchangeEndpoint)} only handles the client_credentials grant, " +
				$"but received grant type '{request.GrantType}'.");

		var clientId = request.ClientId ??
			throw new InvalidOperationException("The authenticated request carries no client_id.");

		// OpenIddict has already authenticated this request against the seeded application (see class
		// doc), so a miss here is an invariant violation, not a user-facing "unknown client" branch: the
		// .Outcome view's failure folds to the endpoint's own contract, an unhandled 500.
		var application = Invariant(
			await manager.Outcome.FindByClientIdAsync(clientId, context.RequestAborted).ConfigureAwait(false),
			$"No application could be found for the already-authenticated client_id '{clientId}'.");
		var applicationId = Guid.Parse(Invariant(
			await manager.Outcome.GetIdAsync(application, context.RequestAborted).ConfigureAwait(false),
			$"The application for client_id '{clientId}' carries no id."));

		// OpenIddictConstants.Claims.Subject ("sub"), not ClaimTypes.NameIdentifier (a different, URI-shaped
		// BCL claim type) -- OpenIddict's token-generation pipeline reads the principal's subject specifically
		// by this claim type, verified by reflection against the installed 7.6.0 package during planning.
		ClaimsIdentity identity = new(
			OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
			OpenIddictConstants.Claims.Subject, ClaimTypes.Role);
		identity.AddClaim(new Claim(OpenIddictConstants.Claims.Subject, clientId).SetDestinations(
			OpenIddictConstants.Destinations.AccessToken));
		// Midgard's PrincipalAccessor.Seed backstop -- see class doc.
		identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, applicationId.ToString()).SetDestinations(
			OpenIddictConstants.Destinations.AccessToken));

		ClaimsPrincipal principal = new(identity);
		principal.SetAudiences("Norse.Facade");

		return Results.SignIn(principal, authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
	}

	static T Invariant<T>(Outcome<T> outcome, string violation)
		where T : notnull =>
		outcome.Match(static value => value,
			problem => throw new InvalidOperationException($"{violation} ({problem.Category})"));
}
