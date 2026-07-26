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
		IRequestHandler<LoginRequest, Outcome<BoolResponse>>? loginHandler = null,
		IRequestHandler<RegisterRequest, Outcome<BoolResponse>>? registerHandler = null,
		IRequestHandler<LogoutRequest, Outcome<Unit>>? logoutHandler = null,
		IDeferredSignIn? deferredSignIn = null,
		HttpContext? httpContext = null)
	{
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(httpContext ?? new DefaultHttpContext());
		return new AuthenticationService(
			loginHandler ?? Substitute.For<IRequestHandler<LoginRequest, Outcome<BoolResponse>>>(),
			registerHandler ?? Substitute.For<IRequestHandler<RegisterRequest, Outcome<BoolResponse>>>(),
			logoutHandler ?? Substitute.For<IRequestHandler<LogoutRequest, Outcome<Unit>>>(),
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
		var loginHandler = Substitute.For<IRequestHandler<LoginRequest, Outcome<BoolResponse>>>();
		loginHandler.Handle(Arg.Any<LoginRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<BoolResponse>.Ok(new BoolResponse { Value = true })));
		var service = CreateService(loginHandler: loginHandler);

		var outcome = await service.Login(new LoginRequest { Email = "a@b.com", Password = "x" });

		outcome.TryGetValue(out Success<LoginResult> success).ShouldBeTrue();
		success.Value.Succeeded.ShouldBeTrue();
		success.Value.DeferredCompletionUrl.ShouldBeNull();
	}

	[Fact]
	async Task Login_BusinessFailure_ReturnsFailedOutcome_NotAThrow_PreservingCategory()
	{
		var loginHandler = Substitute.For<IRequestHandler<LoginRequest, Outcome<BoolResponse>>>();
		loginHandler.Handle(Arg.Any<LoginRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<BoolResponse>.Err(ErrorCategory.LockedOut)));
		var service = CreateService(loginHandler: loginHandler);

		var outcome = await service.Login(new LoginRequest { Email = "a@b.com", Password = "x" });

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.LockedOut);
	}

	[Fact]
	async Task Login_Succeeds_PopulatesDeferredCompletionUrl_WhenStashedOnHttpContext()
	{
		var loginHandler = Substitute.For<IRequestHandler<LoginRequest, Outcome<BoolResponse>>>();
		loginHandler.Handle(Arg.Any<LoginRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<BoolResponse>.Ok(new BoolResponse { Value = true })));
		var httpContext = new DefaultHttpContext();
		httpContext.Items[NorseSignInManager.DeferredSignInKeyItemName] = "stashed-key";
		var service = CreateService(loginHandler: loginHandler, deferredSignIn: CreateEchoingDeferredSignIn(), httpContext: httpContext);

		var outcome = await service.Login(new LoginRequest { Email = "a@b.com", Password = "x" });

		outcome.TryGetValue(out Success<LoginResult> success).ShouldBeTrue();
		success.Value.DeferredCompletionUrl.ShouldNotBeNull();
		success.Value.DeferredCompletionUrl.ShouldContain("stashed-key");
	}

	[Fact]
	async Task Register_Succeeds_ReturnsOkOutcome()
	{
		var registerHandler = Substitute.For<IRequestHandler<RegisterRequest, Outcome<BoolResponse>>>();
		registerHandler.Handle(Arg.Any<RegisterRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<BoolResponse>.Ok(new BoolResponse { Value = true })));
		var service = CreateService(registerHandler: registerHandler);

		var outcome = await service.Register(new RegisterRequest { Email = "a@b.com", Password = "x" });

		outcome.TryGetValue(out Success<Unit> _).ShouldBeTrue();
	}

	[Fact]
	async Task Register_BusinessFailure_ReturnsFailedOutcome_NotAThrow_PreservingCategory()
	{
		var registerHandler = Substitute.For<IRequestHandler<RegisterRequest, Outcome<BoolResponse>>>();
		registerHandler.Handle(Arg.Any<RegisterRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<BoolResponse>.Err(ErrorCategory.Conflict)));
		var service = CreateService(registerHandler: registerHandler);

		var outcome = await service.Register(new RegisterRequest { Email = "a@b.com", Password = "x" });

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Conflict);
	}

	// Logout needs the identical deferred-completion coverage as Login (2026-07-24 correction, found
	// while scoping Task 11) — clearing the auth cookie hits the same Response.HasStarted constraint
	// as setting one, so Logout's TryGetDeferredCompletionUrl() call isn't optional plumbing.

	[Fact]
	async Task Logout_Succeeds_ReturnsLogoutResult_WithNoDeferredCompletionUrl_WhenNoneStashed()
	{
		var logoutHandler = Substitute.For<IRequestHandler<LogoutRequest, Outcome<Unit>>>();
		logoutHandler.Handle(Arg.Any<LogoutRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<Unit>.Ok(Unit.Value)));
		var service = CreateService(logoutHandler: logoutHandler);

		var outcome = await service.Logout(new LogoutRequest());

		outcome.TryGetValue(out Success<LogoutResult> success).ShouldBeTrue();
		success.Value.DeferredCompletionUrl.ShouldBeNull();
	}

	[Fact]
	async Task Logout_Succeeds_PopulatesDeferredCompletionUrl_WhenStashedOnHttpContext()
	{
		var logoutHandler = Substitute.For<IRequestHandler<LogoutRequest, Outcome<Unit>>>();
		logoutHandler.Handle(Arg.Any<LogoutRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<Unit>.Ok(Unit.Value)));
		var httpContext = new DefaultHttpContext();
		httpContext.Items[NorseSignInManager.DeferredSignInKeyItemName] = "stashed-key";
		var service = CreateService(logoutHandler: logoutHandler, deferredSignIn: CreateEchoingDeferredSignIn(), httpContext: httpContext);

		var outcome = await service.Logout(new LogoutRequest());

		outcome.TryGetValue(out Success<LogoutResult> success).ShouldBeTrue();
		success.Value.DeferredCompletionUrl.ShouldNotBeNull();
		success.Value.DeferredCompletionUrl.ShouldContain("stashed-key");
	}

	[Fact]
	async Task Logout_BusinessFailure_ReturnsFailedOutcome_NotAThrow_PreservingCategory()
	{
		var logoutHandler = Substitute.For<IRequestHandler<LogoutRequest, Outcome<Unit>>>();
		logoutHandler.Handle(Arg.Any<LogoutRequest>(), Arg.Any<CancellationToken>())
			.Returns(_ => ValueTask.FromResult(Outcome<Unit>.Err(ErrorCategory.Fault)));
		var service = CreateService(logoutHandler: logoutHandler);

		var outcome = await service.Logout(new LogoutRequest());

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Fault);
	}
}
