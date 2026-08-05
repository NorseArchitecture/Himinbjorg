using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

static class MockRoleManager
{
	public static RoleManager<NorseRole> Create() =>
		Substitute.For<RoleManager<NorseRole>>(
			Substitute.For<IRoleStore<NorseRole>>(), Array.Empty<IRoleValidator<NorseRole>>(),
			new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(),
			NullLogger<RoleManager<NorseRole>>.Instance);
}
