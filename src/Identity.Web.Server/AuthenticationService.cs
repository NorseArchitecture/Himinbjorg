using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components;

namespace Norse.Identity.Web.Server;

/// <summary>
/// Thin forwarder — every method delegates to its matching <see cref="IRequestHandler{TRequest,TResponse}"/>
/// (registered in <see cref="ServiceCollectionExtensions.AddNorseAuthenticationService"/>) does the actual
/// failure translation. No branching, no business logic lives here — spec §9.4/§9.5.
/// </summary>
sealed class AuthenticationService(
/*
IRequestHandler<LoginRequest, Outcome<BoolResponse>> loginHandler,
IRequestHandler<RegisterRequest, Outcome<BoolResponse>> registerHandler,
IRequestHandler<LogoutRequest, Outcome> logoutHandler,
IHttpContextAccessor httpContextAccessor
*/
)
	: IAuthenticationService
{
	public async Task<LoginResult> Login(LoginRequest request) =>
		throw new NotImplementedException(); //new() { Succeeded = (await loginHandler.Handle(request, httpContextAccessor.HttpContext!.RequestAborted).ConfigureAwait(false)).Value };

	public async Task Register(RegisterRequest request) =>
		throw new NotImplementedException(); //registerHandler.Handle(request, httpContextAccessor.HttpContext!.RequestAborted);

	public Task Logout(LogoutRequest request) =>
		throw new NotImplementedException(); //logoutHandler.Handle(request, httpContextAccessor.HttpContext!.RequestAborted);
}
