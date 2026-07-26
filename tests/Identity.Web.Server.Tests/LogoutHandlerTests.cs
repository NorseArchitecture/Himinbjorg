using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

public sealed class LogoutHandlerTests
{
	[Fact]
	async Task Always_returns_a_successful_outcome()
	{
		var signInManager = MockSignInManager.Create();
		LogoutHandler handler = new(signInManager);

		var outcome = await handler.Handle(new LogoutRequest(), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<Unit> _).ShouldBeTrue();
		await signInManager.Received(1).SignOutAsync();
	}
}
