using Microsoft.AspNetCore.Http;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.AuthN.Services;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

public sealed class LogoutHandlerTests
{
	static LogoutHandler CreateHandler(
		Microsoft.AspNetCore.Identity.SignInManager<NorseUser> signInManager,
		IDeferredSignIn? deferredSignIn = null,
		HttpContext? httpContext = null)
	{
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(httpContext ?? new DefaultHttpContext());
		return new LogoutHandler(signInManager, deferredSignIn ?? Substitute.For<IDeferredSignIn>(), accessor);
	}

	[Fact]
	async Task Always_returns_a_successful_outcome()
	{
		var signInManager = MockSignInManager.Create();
		var handler = CreateHandler(signInManager);

		var outcome = await handler.Handle(new LogoutCommand(Unit.Value), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LogoutResult> _).ShouldBeTrue();
		await signInManager.Received(1).SignOutAsync();
	}

	[Fact]
	async Task DeferredCompletionUrl_is_null_when_nothing_is_stashed_on_HttpContext()
	{
		var signInManager = MockSignInManager.Create();
		var handler = CreateHandler(signInManager);

		var outcome = await handler.Handle(new LogoutCommand(Unit.Value), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LogoutResult> success).ShouldBeTrue();
		success.Value.DeferredCompletionUrl.ShouldBeNull();
	}

	[Fact]
	async Task DeferredCompletionUrl_is_populated_when_stashed_on_HttpContext()
	{
		var signInManager = MockSignInManager.Create();
		var deferredSignIn = Substitute.For<IDeferredSignIn>();
		deferredSignIn.BuildCompletionUrl(Arg.Any<string>(), Arg.Any<string>())
			.Returns(call => $"/_auth/complete?key={call.ArgAt<string>(0)}&returnUrl={Uri.EscapeDataString(call.ArgAt<string>(1))}");
		DefaultHttpContext httpContext = new();
		httpContext.Items[NorseSignInManager.DeferredSignInKeyItemName] = "stashed-key";
		var handler = CreateHandler(signInManager, deferredSignIn, httpContext);

		var outcome = await handler.Handle(new LogoutCommand(Unit.Value), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LogoutResult> success).ShouldBeTrue();
		success.Value.DeferredCompletionUrl.ShouldNotBeNull();
		success.Value.DeferredCompletionUrl.ShouldContain("stashed-key");
	}
}
