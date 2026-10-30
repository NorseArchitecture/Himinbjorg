using System.Globalization;
using System.Security.Claims;
using Norse.Abstractions.Components.Authorization;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Norse.Identity.Web.Server.OpenIddict;

/// <summary>
///     The minted user principal (2026-10-29 OpenIddict spec §5.3), shared by the authorize endpoint and the token
///     endpoint's refresh: <c>sub</c> and <see cref="ClaimTypes.NameIdentifier" /> (the same opaque user id; Midgard's
///     <c>PrincipalAccessor.Seed</c> requires the latter, as the machine exchange already does), <c>auth_time</c> and
///     <see cref="StampClaimType" />. Never roles, never an email or a name. The stamp has no access-token or id-token
///     destination: codes and refresh tokens are server-only and carry the principal's claims regardless.
/// </summary>
static class UserPrincipalFactory
{
	/// <summary>The security stamp's private claim, carried by codes and refresh tokens only.</summary>
	internal const string StampClaimType = "norse_stamp";

	/// <summary>Builds the principal OpenIddict signs, audience <see cref="NorseAudiences.User" />.</summary>
	/// <param name="userId">The opaque user id.</param>
	/// <param name="authTime">When the credential was presented, in integral epoch seconds.</param>
	/// <param name="stamp">The security stamp of the authentication that produced the grant (T4-8).</param>
	/// <param name="scopes">The granted scopes.</param>
	internal static ClaimsPrincipal Create(Guid userId, long authTime, string stamp, IEnumerable<string> scopes)
	{
		var subject = userId.ToString();
		ClaimsIdentity identity = new(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
			OpenIddictConstants.Claims.Subject, OpenIddictConstants.Claims.Role);
		identity.AddClaim(new Claim(OpenIddictConstants.Claims.Subject, subject).SetDestinations(
			OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken));
		identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, subject).SetDestinations(
			OpenIddictConstants.Destinations.AccessToken));
		identity.AddClaim(new Claim(NorseClaimTypes.AuthTime, authTime.ToString(CultureInfo.InvariantCulture),
			ClaimValueTypes.Integer64).SetDestinations(
			OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken));
		identity.AddClaim(new Claim(StampClaimType, stamp));

		ClaimsPrincipal principal = new(identity);
		principal.SetScopes(scopes);
		principal.SetAudiences(NorseAudiences.User);
		return principal;
	}
}
