using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server;

/// <summary>
/// The claims allowlist (2026-08-03 PII spec §4.4): the base factory builds, then everything outside
/// the closed set — opaque GUID, roles, security stamp — is dropped. Allowlist, not strip-list: a
/// claim Microsoft adds in a future release is dropped by construction, never leaked by omission.
/// The security-stamp claim stays because <c>SecurityStampValidator</c> revalidation is the
/// mechanism that kills a dead user's live sessions after the shred ceremony rotates the stamp.
/// <c>ClaimTypes.Name</c> is omitted: display names come from the disclosure surface, masked.
/// </summary>
public sealed class NorseUserClaimsPrincipalFactory(
	UserManager<NorseUser> userManager, RoleManager<NorseRole> roleManager, IOptions<IdentityOptions> options) :
	UserClaimsPrincipalFactory<NorseUser, NorseRole>(userManager, roleManager, options)
{
	/// <inheritdoc />
	public override async Task<ClaimsPrincipal> CreateAsync(NorseUser user)
	{
		var principal = await base.CreateAsync(user).ConfigureAwait(false);
		var identity = (ClaimsIdentity)principal.Identity!;
		var claims = Options.ClaimsIdentity;
		string[] allowed = [claims.UserIdClaimType, claims.RoleClaimType, claims.SecurityStampClaimType];
		foreach (var claim in identity.Claims.Where(c => !allowed.Contains(c.Type, StringComparer.Ordinal)).ToArray())
			identity.RemoveClaim(claim);
		return principal;
	}
}
