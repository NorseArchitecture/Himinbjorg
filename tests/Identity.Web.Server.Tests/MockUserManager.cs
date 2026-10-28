using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;

namespace Norse.Identity.Web.Server.Tests;

static class MockUserManager
{
	public static UserManager<NorseUser> Create() =>
		Substitute.For<UserManager<NorseUser>>(Arguments());

	/// <summary>
	///     A substitute that also carries <c>NorseUserManager</c>'s lossless seams, so the <c>.Outcome</c> views over
	///     <see cref="IRecoveryCodeReplacement" /> and <see cref="IAuthenticatorKeyProvisioning" /> reach it; arrange
	///     them through a cast.
	/// </summary>
	public static UserManager<NorseUser> CreateLossless() =>
		Substitute.For<UserManager<NorseUser>, IRecoveryCodeReplacement, IAuthenticatorKeyProvisioning>(Arguments());

	static object[] Arguments() =>
	[
		Substitute.For<IUserStore<NorseUser>>(), null!, new PasswordHasher<NorseUser>(),
		Array.Empty<IUserValidator<NorseUser>>(), Array.Empty<IPasswordValidator<NorseUser>>(),
		new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(), null!,
		NullLogger<UserManager<NorseUser>>.Instance
	];
}
