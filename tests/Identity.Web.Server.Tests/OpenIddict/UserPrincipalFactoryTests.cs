using System.Security.Claims;
using Norse.Abstractions.Components.Authorization;
using Norse.Identity.Web.Server.OpenIddict;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;

namespace Norse.Identity.Web.Server.Tests.OpenIddict;

/// <summary>The minted user principal (spec §5.3): four claims, their destinations, the scopes and the user audience.</summary>
public sealed class UserPrincipalFactoryTests
{
	static readonly Guid _userId = Guid.NewGuid();

	static ClaimsPrincipal Principal =>
		UserPrincipalFactory.Create(_userId, 1_700_000_000, "the-stamp",
			[OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess]);

	[Fact]
	void The_principal_carries_exactly_sub_name_identifier_auth_time_and_the_stamp()
	{
		// OpenIddict's own private claims (oi_scp, oi_aud) carry the scopes and audiences, asserted below.
		var claims = Principal.Claims
			.Where(static claim => !claim.Type.StartsWith("oi_", StringComparison.Ordinal))
			.Select(static claim => (claim.Type, claim.Value, claim.ValueType))
			.ToList();

		claims.Count.ShouldBe(4);
		claims.ShouldContain((OpenIddictConstants.Claims.Subject, _userId.ToString(), ClaimValueTypes.String));
		claims.ShouldContain((ClaimTypes.NameIdentifier, _userId.ToString(), ClaimValueTypes.String));
		claims.ShouldContain((NorseClaimTypes.AuthTime, "1700000000", ClaimValueTypes.Integer64));
		claims.ShouldContain((UserPrincipalFactory.StampClaimType, "the-stamp", ClaimValueTypes.String));
	}

	[Fact]
	void Destinations_keep_the_stamp_out_of_both_public_tokens()
	{
		var principal = Principal;

		Destinations(principal, OpenIddictConstants.Claims.Subject).ShouldBe(
			[OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken], true);
		Destinations(principal, ClaimTypes.NameIdentifier).ShouldBe([OpenIddictConstants.Destinations.AccessToken]);
		Destinations(principal, NorseClaimTypes.AuthTime).ShouldBe(
			[OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken], true);
		Destinations(principal, UserPrincipalFactory.StampClaimType).ShouldBeEmpty();
	}

	[Fact]
	void The_principal_is_the_server_scheme_s_with_the_scopes_and_the_user_audience()
	{
		var principal = Principal;

		principal.Identity.ShouldNotBeNull().AuthenticationType.ShouldBe(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
		principal.GetScopes().ShouldBe([OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.OfflineAccess], true);
		principal.GetAudiences().ShouldBe([NorseAudiences.User]);
		principal.FindFirst(ClaimTypes.Role).ShouldBeNull();
		principal.FindFirst(OpenIddictConstants.Claims.Role).ShouldBeNull();
	}

	static string[] Destinations(ClaimsPrincipal principal, string type) =>
		[.. principal.FindFirst(type).ShouldNotBeNull().GetDestinations()];
}
