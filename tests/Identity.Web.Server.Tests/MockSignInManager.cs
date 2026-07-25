using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Norse.Identity.Web.Server.Tests;

static class MockSignInManager
{
	public static SignInManager<NorseUser> Create()
	{
		var userManager = Substitute.For<UserManager<NorseUser>>(
			Substitute.For<IUserStore<NorseUser>>(), null!, new PasswordHasher<NorseUser>(),
			Array.Empty<IUserValidator<NorseUser>>(), Array.Empty<IPasswordValidator<NorseUser>>(),
			new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null!,
			NullLogger<UserManager<NorseUser>>.Instance);

		return Substitute.For<SignInManager<NorseUser>>(
			userManager, new HttpContextAccessor(),
			Substitute.For<IUserClaimsPrincipalFactory<NorseUser>>(),
			Options.Create(new IdentityOptions()), NullLogger<SignInManager<NorseUser>>.Instance,
			Substitute.For<Microsoft.AspNetCore.Authentication.IAuthenticationSchemeProvider>(),
			Substitute.For<IUserConfirmation<NorseUser>>());
	}
}
