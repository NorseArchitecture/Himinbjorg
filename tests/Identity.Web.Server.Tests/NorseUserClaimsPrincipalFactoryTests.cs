using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

public sealed class NorseUserClaimsPrincipalFactoryTests
{
	static NorseUserClaimsPrincipalFactory CreateFactory(NorseUser user, string[] roles, Claim[] storedClaims)
	{
		using var userManager = MockUserManager.Create();
		userManager.GetUserIdAsync(user).Returns(user.Id.ToString());
		userManager.GetUserNameAsync(user).Returns(user.UserName);
		userManager.GetEmailAsync(user).Returns(user.Email);
		userManager.SupportsUserEmail.Returns(true);
		userManager.SupportsUserSecurityStamp.Returns(true);
		userManager.GetSecurityStampAsync(user).Returns(user.SecurityStamp);
		userManager.SupportsUserClaim.Returns(true);
		userManager.GetClaimsAsync(user).Returns(storedClaims);
		userManager.SupportsUserRole.Returns(true);
		userManager.GetRolesAsync(user).Returns(roles);
		using var roleManager = MockRoleManager.Create();
		roleManager.SupportsRoleClaims.Returns(false);
		var options = Microsoft.Extensions.Options.Options.Create(new IdentityOptions());
		return new(userManager, roleManager, options);
	}

	[Fact]
	async Task Principal_carries_exactly_the_closed_claim_set_and_nothing_else()
	{
		NorseUser user = new()
		{
			Id = Guid.NewGuid(),
			UserName = "buvy@example.com",
			Email = "buvy@example.com",
			PhoneNumber = "+15551234567",
			SecurityStamp = Guid.NewGuid().ToString("N")
		};
		var factory = CreateFactory(user, ["admin"], [new("favorite_color", "green")]);
		var principal = await factory.CreateAsync(user);
		var options = new IdentityOptions().ClaimsIdentity;
		principal.Claims
			.Select(c => c.Type)
			.Distinct()
			.Order()
			.ShouldBe(new[] { options.RoleClaimType, options.SecurityStampClaimType, options.UserIdClaimType }.Order(),
				ignoreOrder: true); // EXACT closed set -- any surplus claim fails this test
		principal.Identity!.Name.ShouldBeNull(); // Name claim deliberately dropped
		principal.FindFirst(options.UserIdClaimType)!.Value.ShouldBe(user.Id.ToString());
		principal.FindFirst(options.SecurityStampClaimType)!.Value.ShouldBe(user.SecurityStamp);
		principal.IsInRole("admin").ShouldBeTrue();
	}
}
