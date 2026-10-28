using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;
using Norse.Identity.Web.Server.SignInMethods;

namespace Norse.Identity.Web.Server.Tests.SignInMethods;

/// <summary>
///     <see cref="GetPasskeyRequestOptionsHandler" />, over a real <see cref="NorseSignInManager" /> on
///     <see cref="TwoFactorHarness" />: the request options for no particular user, and the assertion state protected
///     under the assertion purpose.
/// </summary>
public sealed class GetPasskeyRequestOptionsHandlerTests
{
	static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact]
	async Task Answers_the_options_and_the_protected_state()
	{
		using var harness = await TwoFactorHarness.StartAsync();
		harness.PasskeyHandler.MakeRequestOptionsAsync(Arg.Any<NorseUser?>(), Arg.Any<HttpContext>())
			.Returns(new PasskeyRequestOptionsResult { RequestOptionsJson = "{}", AssertionState = "state" });

		var outcome = (await harness.RunAsync(manager =>
			new GetPasskeyRequestOptionsHandler(manager).Handle(new(Unit.Value), Cancellation).AsTask())).Value;

		var response = BaseRequest.ValueOf(outcome.ShouldNotBeNull());
		response.OptionsJson.ShouldBe("{}");
		harness.AssertionProtector.Unprotect(response.AssertionState).ShouldBe("state");
		await harness.PasskeyHandler.Received(1).MakeRequestOptionsAsync(null, Arg.Any<HttpContext>());
	}
}
