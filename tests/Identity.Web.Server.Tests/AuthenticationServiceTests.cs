using Grpc.Core;
using Microsoft.AspNetCore.Http;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using NSubstitute;
using Shouldly;

namespace Norse.Identity.Web.Server.Tests;

public sealed class AuthenticationServiceTests
{
	[Fact]
	async Task Login_Succeeds_ReturnsLoginResult_WithNoDeferredCompletionUrl_WhenNoneStashed()
	{
		var loginHandler = Substitute.For<IRequestHandler<LoginRequest, Outcome<BoolResponse>>>();
		loginHandler.Handle(Arg.Any<LoginRequest>(), Arg.Any<CancellationToken>())
			.Returns(ValueTask.FromResult(Outcome<BoolResponse>.Ok(new BoolResponse { Value = true })));
		var httpContext = new DefaultHttpContext();
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(httpContext);
		var service = new AuthenticationService(
			loginHandler,
			Substitute.For<IRequestHandler<RegisterRequest, Outcome<BoolResponse>>>(),
			Substitute.For<IRequestHandler<LogoutRequest, Norse.Abstractions.Contracts.Outcome<Unit>>>(),
			accessor);

		var result = await service.Login(new LoginRequest { Email = "a@b.com", Password = "x" });

		result.Succeeded.ShouldBeTrue();
		result.DeferredCompletionUrl.ShouldBeNull();
	}

	[Fact]
	async Task Login_BusinessFailure_ThrowsRpcExceptionWithErrorInfo_NotNotImplementedException()
	{
		var loginHandler = Substitute.For<IRequestHandler<LoginRequest, Outcome<BoolResponse>>>();
		loginHandler.Handle(Arg.Any<LoginRequest>(), Arg.Any<CancellationToken>())
			.Returns(ValueTask.FromResult(Outcome<BoolResponse>.Err(ErrorCategory.LockedOut)));
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(new DefaultHttpContext());
		var service = new AuthenticationService(
			loginHandler,
			Substitute.For<IRequestHandler<RegisterRequest, Outcome<BoolResponse>>>(),
			Substitute.For<IRequestHandler<LogoutRequest, Norse.Abstractions.Contracts.Outcome<Unit>>>(),
			accessor);

		var exception = await Should.ThrowAsync<RpcException>(async () =>
			await service.Login(new LoginRequest { Email = "a@b.com", Password = "x" }));

		exception.StatusCode.ShouldBe(StatusCode.PermissionDenied);
	}

	[Fact]
	async Task Login_Succeeds_PopulatesDeferredCompletionUrl_WhenStashedOnHttpContext()
	{
		var loginHandler = Substitute.For<IRequestHandler<LoginRequest, Outcome<BoolResponse>>>();
		loginHandler.Handle(Arg.Any<LoginRequest>(), Arg.Any<CancellationToken>())
			.Returns(ValueTask.FromResult(Outcome<BoolResponse>.Ok(new BoolResponse { Value = true })));
		var httpContext = new DefaultHttpContext();
		httpContext.Items[NorseSignInManager.DeferredSignInKeyItemName] = "stashed-key";
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(httpContext);
		var service = new AuthenticationService(
			loginHandler,
			Substitute.For<IRequestHandler<RegisterRequest, Outcome<BoolResponse>>>(),
			Substitute.For<IRequestHandler<LogoutRequest, Norse.Abstractions.Contracts.Outcome<Unit>>>(),
			accessor);

		var result = await service.Login(new LoginRequest { Email = "a@b.com", Password = "x" });

		result.DeferredCompletionUrl.ShouldNotBeNull();
		result.DeferredCompletionUrl.ShouldContain("stashed-key");
	}

	// Logout needs the identical deferred-completion coverage as Login (2026-07-24 correction, found
	// while scoping Task 11) — clearing the auth cookie hits the same Response.HasStarted constraint
	// as setting one, so Logout's TryGetDeferredCompletionUrl() call isn't optional plumbing.

	[Fact]
	async Task Logout_Succeeds_ReturnsLogoutResult_WithNoDeferredCompletionUrl_WhenNoneStashed()
	{
		var logoutHandler = Substitute.For<IRequestHandler<LogoutRequest, Norse.Abstractions.Contracts.Outcome<Unit>>>();
		logoutHandler.Handle(Arg.Any<LogoutRequest>(), Arg.Any<CancellationToken>())
			.Returns(ValueTask.FromResult(Outcome.Ok(Unit.Value)));
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(new DefaultHttpContext());
		var service = new AuthenticationService(
			Substitute.For<IRequestHandler<LoginRequest, Outcome<BoolResponse>>>(),
			Substitute.For<IRequestHandler<RegisterRequest, Outcome<BoolResponse>>>(),
			logoutHandler,
			accessor);

		var result = await service.Logout(new LogoutRequest());

		result.DeferredCompletionUrl.ShouldBeNull();
	}

	[Fact]
	async Task Logout_Succeeds_PopulatesDeferredCompletionUrl_WhenStashedOnHttpContext()
	{
		var logoutHandler = Substitute.For<IRequestHandler<LogoutRequest, Norse.Abstractions.Contracts.Outcome<Unit>>>();
		logoutHandler.Handle(Arg.Any<LogoutRequest>(), Arg.Any<CancellationToken>())
			.Returns(ValueTask.FromResult(Outcome.Ok(Unit.Value)));
		var httpContext = new DefaultHttpContext();
		httpContext.Items[NorseSignInManager.DeferredSignInKeyItemName] = "stashed-key";
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(httpContext);
		var service = new AuthenticationService(
			Substitute.For<IRequestHandler<LoginRequest, Outcome<BoolResponse>>>(),
			Substitute.For<IRequestHandler<RegisterRequest, Outcome<BoolResponse>>>(),
			logoutHandler,
			accessor);

		var result = await service.Logout(new LogoutRequest());

		result.DeferredCompletionUrl.ShouldNotBeNull();
		result.DeferredCompletionUrl.ShouldContain("stashed-key");
	}

	[Fact]
	async Task Logout_BusinessFailure_ThrowsRpcExceptionWithErrorInfo()
	{
		var logoutHandler = Substitute.For<IRequestHandler<LogoutRequest, Norse.Abstractions.Contracts.Outcome<Unit>>>();
		logoutHandler.Handle(Arg.Any<LogoutRequest>(), Arg.Any<CancellationToken>())
			.Returns(ValueTask.FromResult(Outcome.Err(ErrorCategory.Fault)));
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(new DefaultHttpContext());
		var service = new AuthenticationService(
			Substitute.For<IRequestHandler<LoginRequest, Outcome<BoolResponse>>>(),
			Substitute.For<IRequestHandler<RegisterRequest, Outcome<BoolResponse>>>(),
			logoutHandler,
			accessor);

		await Should.ThrowAsync<RpcException>(async () => await service.Logout(new LogoutRequest()));
	}
}
