using Microsoft.AspNetCore.Http;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

public sealed class AuthenticationServiceTests
{
	static AuthenticationService CreateService(
		ISender? sender = null,
		IDeferredSignIn? deferredSignIn = null,
		HttpContext? httpContext = null)
	{
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(httpContext ?? new DefaultHttpContext());
		return new AuthenticationService(
			sender ?? Substitute.For<ISender>(),
			deferredSignIn ?? Substitute.For<IDeferredSignIn>(),
			accessor);
	}

	static IDeferredSignIn CreateEchoingDeferredSignIn()
	{
		var deferredSignIn = Substitute.For<IDeferredSignIn>();
		deferredSignIn.BuildCompletionUrl(Arg.Any<string>(), Arg.Any<string>())
			.Returns(call => $"/_auth/complete?key={call.ArgAt<string>(0)}&returnUrl={Uri.EscapeDataString(call.ArgAt<string>(1))}");
		return deferredSignIn;
	}

	[Fact]
	async Task Login_Succeeds_ReturnsLoginResult_WithNoDeferredCompletionUrl_WhenNoneStashed()
	{
		var sender = Substitute.For<ISender>();
		sender.Send(Arg.Any<LoginRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<BoolResponse>.Ok(new BoolResponse { Value = true })));
		var service = CreateService(sender: sender);

		var outcome = await service.Login(new LoginRequest { Email = "a@b.com", Password = "x" }, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LoginResult> success).ShouldBeTrue();
		success.Value.Succeeded.ShouldBeTrue();
		success.Value.DeferredCompletionUrl.ShouldBeNull();
	}

	[Fact]
	async Task Login_BusinessFailure_ReturnsFailedOutcome_NotAThrow_PreservingCategory()
	{
		var sender = Substitute.For<ISender>();
		sender.Send(Arg.Any<LoginRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<BoolResponse>.Err(ErrorCategory.LockedOut)));
		var service = CreateService(sender: sender);

		var outcome = await service.Login(new LoginRequest { Email = "a@b.com", Password = "x" }, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.LockedOut);
	}

	[Fact]
	async Task Login_Succeeds_PopulatesDeferredCompletionUrl_WhenStashedOnHttpContext()
	{
		var sender = Substitute.For<ISender>();
		sender.Send(Arg.Any<LoginRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<BoolResponse>.Ok(new BoolResponse { Value = true })));
		DefaultHttpContext httpContext = new();
		httpContext.Items[NorseSignInManager.DeferredSignInKeyItemName] = "stashed-key";
		var service = CreateService(sender: sender, deferredSignIn: CreateEchoingDeferredSignIn(), httpContext: httpContext);

		var outcome = await service.Login(new LoginRequest { Email = "a@b.com", Password = "x" }, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LoginResult> success).ShouldBeTrue();
		success.Value.DeferredCompletionUrl.ShouldNotBeNull();
		success.Value.DeferredCompletionUrl.ShouldContain("stashed-key");
	}

	[Fact]
	async Task Register_Succeeds_ReturnsOkOutcome()
	{
		var sender = Substitute.For<ISender>();
		sender.Send(Arg.Any<RegisterRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<BoolResponse>.Ok(new BoolResponse { Value = true })));
		var service = CreateService(sender: sender);

		var outcome = await service.Register(new RegisterRequest { Email = "a@b.com", Password = "x" }, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<Unit> _).ShouldBeTrue();
	}

	[Fact]
	async Task Register_BusinessFailure_ReturnsFailedOutcome_NotAThrow_PreservingCategory()
	{
		var sender = Substitute.For<ISender>();
		sender.Send(Arg.Any<RegisterRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<BoolResponse>.Err(ErrorCategory.Conflict)));
		var service = CreateService(sender: sender);

		var outcome = await service.Register(new RegisterRequest { Email = "a@b.com", Password = "x" }, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Conflict);
	}

	// Logout needs the identical deferred-completion coverage as Login (2026-07-24 correction, found
	// while scoping Task 11) — clearing the auth cookie hits the same Response.HasStarted constraint
	// as setting one, so Logout's TryGetDeferredCompletionUrl() call isn't optional plumbing.

	[Fact]
	async Task Logout_Succeeds_ReturnsLogoutResult_WithNoDeferredCompletionUrl_WhenNoneStashed()
	{
		var sender = Substitute.For<ISender>();
		sender.Send(Arg.Any<LogoutRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<Unit>.Ok(Unit.Value)));
		var service = CreateService(sender: sender);

		var outcome = await service.Logout(new LogoutRequest(), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LogoutResult> success).ShouldBeTrue();
		success.Value.DeferredCompletionUrl.ShouldBeNull();
	}

	[Fact]
	async Task Logout_Succeeds_PopulatesDeferredCompletionUrl_WhenStashedOnHttpContext()
	{
		var sender = Substitute.For<ISender>();
		sender.Send(Arg.Any<LogoutRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<Unit>.Ok(Unit.Value)));
		DefaultHttpContext httpContext = new();
		httpContext.Items[NorseSignInManager.DeferredSignInKeyItemName] = "stashed-key";
		var service = CreateService(sender: sender, deferredSignIn: CreateEchoingDeferredSignIn(), httpContext: httpContext);

		var outcome = await service.Logout(new LogoutRequest(), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<LogoutResult> success).ShouldBeTrue();
		success.Value.DeferredCompletionUrl.ShouldNotBeNull();
		success.Value.DeferredCompletionUrl.ShouldContain("stashed-key");
	}

	[Fact]
	async Task Logout_BusinessFailure_ReturnsFailedOutcome_NotAThrow_PreservingCategory()
	{
		var sender = Substitute.For<ISender>();
		sender.Send(Arg.Any<LogoutRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<Unit>.Err(ErrorCategory.Fault)));
		var service = CreateService(sender: sender);

		var outcome = await service.Logout(new LogoutRequest(), TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Fault);
	}
}
