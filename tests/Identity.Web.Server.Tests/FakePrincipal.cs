using System.Security.Claims;
using Norse.Abstractions.Web.Server.Mediator;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
/// Builds a fake <see cref="IPrincipalAccessor"/> whose principal carries only the given subject's
/// <see cref="ClaimTypes.NameIdentifier"/> claim -- <see cref="DisclosureHandlerTests"/>'s stand-in
/// for the gRPC seeding interceptor or circuit <c>AuthenticationStateProvider</c> that seeds a real
/// one in production.
/// </summary>
static class FakePrincipal
{
	/// <summary>Returns an <see cref="IPrincipalAccessor"/> whose principal authenticates as <paramref name="subjectId"/>.</summary>
	public static IPrincipalAccessor For(Guid subjectId)
	{
		ClaimsIdentity identity = new([new Claim(ClaimTypes.NameIdentifier, subjectId.ToString())], "Test");
		return Wrap(new ClaimsPrincipal(identity));
	}

	/// <summary>Returns an <see cref="IPrincipalAccessor"/> whose principal carries no claims at all -- the missing-user-id-claim case.</summary>
	public static IPrincipalAccessor Empty() =>
		Wrap(new ClaimsPrincipal(new ClaimsIdentity("Test")));

	static IPrincipalAccessor Wrap(ClaimsPrincipal principal)
	{
		var accessor = Substitute.For<IPrincipalAccessor>();
		accessor.GetPrincipalAsync(Arg.Any<CancellationToken>()).Returns(_ => ValueTask.FromResult(principal));
		return accessor;
	}
}
