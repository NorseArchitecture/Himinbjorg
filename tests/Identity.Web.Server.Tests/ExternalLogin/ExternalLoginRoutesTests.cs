namespace Norse.Identity.Web.Server.Tests.ExternalLogin;

public sealed class ExternalLoginRoutesTests
{
	// The set ReturnUrls refuses as a landing: a writable array would let any caller in the assembly unrefuse a start.
	[Fact]
	void The_route_set_cannot_be_written()
	{
		var routes = (IList<string>)ExternalLoginRoutes.All;

		Should.Throw<NotSupportedException>(() => routes[0] = routes[0]);
	}
}
