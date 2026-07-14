using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components;
using Norse.Infrastructure.Web.Server.Mediator.Grpc;

namespace Norse.Identity.Web.Server;

/// <summary>
/// Thin forwarder — every method delegates to its matching <see cref="IRequestHandler{TRequest,TResponse}"/>
/// and calls <see cref="OutcomeExtensions.ThrowIfFailed{T}"/>; <see cref="OutcomeServerInterceptor"/>
/// (registered in <see cref="ServiceCollectionExtensions.AddNorseAuthenticationService"/>) does the actual
/// failure translation. No branching, no business logic lives here — spec §9.4/§9.5.
/// </summary>
sealed class AuthenticationService(
	IRequestHandler<LoginRequest, Outcome<BoolResponse>> loginHandler,
	IRequestHandler<RegisterRequest, Outcome<BoolResponse>> registerHandler,
	IRequestHandler<LogoutRequest, Outcome> logoutHandler,
	IHttpContextAccessor httpContextAccessor)
	: IAuthenticationService
{
	public async Task<LoginResult> Login(LoginRequest request) =>
		new() { Succeeded = (await loginHandler.Handle(request, httpContextAccessor.HttpContext!.RequestAborted).ConfigureAwait(false)).ThrowIfFailed().Value };

	public async Task Register(RegisterRequest request) =>
		(await registerHandler.Handle(request, httpContextAccessor.HttpContext!.RequestAborted).ConfigureAwait(false)).ThrowIfFailed();

	public async Task Logout(LogoutRequest request) =>
		(await logoutHandler.Handle(request, httpContextAccessor.HttpContext!.RequestAborted).ConfigureAwait(false)).ThrowIfFailed();
}
