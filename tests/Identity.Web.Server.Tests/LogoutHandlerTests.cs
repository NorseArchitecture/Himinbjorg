using Norse.AuthN.Components;

namespace Norse.Identity.Web.Server.Tests;

public sealed class LogoutHandlerTests
{
	[Fact]
	async Task Always_returns_a_successful_outcome()
	{
		var signInManager = MockSignInManager.Create();
		var handler = new LogoutHandler(signInManager);

		var outcome = await handler.Handle(new LogoutRequest(), CancellationToken.None);

		outcome.IsSuccess.ShouldBeTrue();
		await signInManager.Received(1).SignOutAsync();
	}
}
