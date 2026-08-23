using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.JsonWebTokens;
using OpenIddict.Abstractions;

namespace Norse.Identity.Web.Server.Tests;

[Collection(PostgresTestGroup.Name)]
public sealed class OpenIddictTokenEndpointTests(PostgresIdentityFixture fixture)
{
	[Fact]
	async Task A_seeded_client_obtains_a_JWT_via_client_credentials()
	{
		var manager = fixture.CreateApplicationManager();
		await manager.CreateAsync(new OpenIddictApplicationDescriptor
		{
			ClientId = "test-machine-client",
			ClientSecret = "test-secret-value",
			ClientType = OpenIddictConstants.ClientTypes.Confidential,
			Permissions =
			{
				OpenIddictConstants.Permissions.Endpoints.Token,
				OpenIddictConstants.Permissions.GrantTypes.ClientCredentials
			}
		}, TestContext.Current.CancellationToken);

		// The fix reads the seeded application's own Id (a real Guid, per NorseOpenIddictApplication)
		// back out via FindByClientIdAsync -- the same lookup PrincipalAccessor.Seed's GUID backstop
		// (Midgard, 2026-08-21) needs satisfied on the issued token's principal. Looking it up here,
		// independently of the fix code path, is what makes the assertion below a real cross-check
		// rather than a tautology.
		var seededApplication = await manager.FindByClientIdAsync("test-machine-client",
			TestContext.Current.CancellationToken) ??
			throw new InvalidOperationException("The just-seeded application cannot be found by client_id.");
		var seededApplicationId = await manager.GetIdAsync(seededApplication, TestContext.Current.CancellationToken);
		var expectedGuid = Guid.Parse(seededApplicationId ??
			throw new InvalidOperationException("The seeded application carries no id."));

		using var client = fixture.CreateTestClient();
		using FormUrlEncodedContent content = new(new Dictionary<string, string>
		{
			["grant_type"] = "client_credentials",
			["client_id"] = "test-machine-client",
			["client_secret"] = "test-secret-value"
		});
		using var response = await client.PostAsync(new Uri("/connect/token", UriKind.Relative), content,
			TestContext.Current.CancellationToken);

		response.EnsureSuccessStatusCode();
		var payload = await response.Content.ReadFromJsonAsync<TokenResponse>(TestContext.Current.CancellationToken);
		payload.ShouldNotBeNull();

		var jwt = new JsonWebToken(payload.AccessToken);
		jwt.GetClaim(OpenIddictConstants.Claims.Subject).Value.ShouldBe("test-machine-client");
		jwt.Audiences.ShouldContain("Norse.Facade");

		// ClaimTypes.NameIdentifier's full URI form -- ASP.NET Core's default claim-type mapping, which
		// OpenIddict's own JWT serializer does not override for claims added via AddClaim/SetDestinations.
		var nameIdentifierClaim = jwt.GetClaim(ClaimTypes.NameIdentifier);
		nameIdentifierClaim.ShouldNotBeNull();
		Guid.TryParse(nameIdentifierClaim.Value, out var actualGuid).ShouldBeTrue();
		actualGuid.ShouldNotBe(Guid.Empty);
		actualGuid.ShouldBe(expectedGuid);
	}

	[Fact]
	async Task An_unsupported_grant_type_is_rejected_before_reaching_application_code()
	{
		using var client = fixture.CreateTestClient();
		using FormUrlEncodedContent content = new(new Dictionary<string, string>
		{
			["grant_type"] = "password",
			["username"] = "irrelevant",
			["password"] = "irrelevant"
		});
		using var response = await client.PostAsync(new Uri("/connect/token", UriKind.Relative), content,
			TestContext.Current.CancellationToken);

		response.IsSuccessStatusCode.ShouldBeFalse();
	}

	// The OAuth2 token response is snake_case on the wire (access_token/token_type/expires_in) -- System.Text.Json's
	// default case-insensitive matching only folds case, not underscores, so without these attributes every
	// property would deserialize to its type default and payload.AccessToken would silently be null instead of
	// throwing, masking a real failure as a false pass.
	sealed record TokenResponse(
		[property: JsonPropertyName("access_token")] string AccessToken,
		[property: JsonPropertyName("token_type")] string TokenType,
		[property: JsonPropertyName("expires_in")] int ExpiresIn);
}
