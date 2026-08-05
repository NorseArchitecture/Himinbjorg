using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

static class TestUserManager
{
	public static NorseUserManager Create(IUserStore<NorseUser> store) =>
		new(store, null!, new PasswordHasher<NorseUser>(),
			[], [],
			new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null!,
			NullLogger<UserManager<NorseUser>>.Instance);
}
