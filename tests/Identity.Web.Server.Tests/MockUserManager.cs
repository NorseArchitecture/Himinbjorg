using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

static class MockUserManager
{
	public static UserManager<NorseUser> Create() =>
		Substitute.For<UserManager<NorseUser>>(
			Substitute.For<IUserStore<NorseUser>>(), null!, new PasswordHasher<NorseUser>(),
			Array.Empty<IUserValidator<NorseUser>>(), Array.Empty<IPasswordValidator<NorseUser>>(),
			new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null!,
			NullLogger<UserManager<NorseUser>>.Instance);
}
