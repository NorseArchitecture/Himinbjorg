using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Infrastructure.Web.Server.DeferredSignIn;
using Norse.Infrastructure.Web.Server.Mediator.Grpc;
using Norse.Primitives;

namespace Norse.Identity.Web.Server;

/// <summary>
/// The reference backend for Heimdall's <see cref="IAuthenticationService"/> contract — Himinbjörg
/// owns this because it needs EF/Identity access, not because it's the only legal implementation.
/// Expected business failures throw <c>Problem.ToRpcException()</c> directly — the one place in this
/// chain where a return value genuinely isn't an option, because a gRPC method's only way to signal
/// non-OK status is to throw. Public: Yggdrasil's composition root maps this type directly.
///
/// <c>[Authorize]</c> is mirrored from the interface onto every method here deliberately, not
/// redundantly — ASP.NET Core's gRPC endpoint metadata is gathered by reflecting on this concrete
/// runtime type, not the interface it implements; an interface method's attributes are not visible
/// to that discovery. Without this mirror, decided law item 4's "enforced on every channel" claim is
/// false for the wire channel specifically, even though the interface declares the policy correctly
/// (spec Remand 3, 2026-07-24 review).
/// </summary>
public sealed class AuthenticationService(
	IRequestHandler<LoginRequest, Outcome<BoolResponse>> loginHandler,
	IRequestHandler<RegisterRequest, Outcome<BoolResponse>> registerHandler,
	IRequestHandler<LogoutRequest, Outcome> logoutHandler,
	IHttpContextAccessor httpContextAccessor)
	: IAuthenticationService
{
	/// <inheritdoc />
	[Microsoft.AspNetCore.Authorization.Authorize(Policy = AuthNPolicies.Public)]
	public async Task<LoginResult> Login(LoginRequest request)
	{
		var outcome = await loginHandler.Handle(request, httpContextAccessor.HttpContext!.RequestAborted).ConfigureAwait(false);
		return outcome switch
		{
			Success<BoolResponse>(var value) => new LoginResult { Succeeded = value.Value, DeferredCompletionUrl = TryGetDeferredCompletionUrl() },
			Failed(var problem) => throw problem.ToRpcException(),
		};
	}

	/// <inheritdoc />
	[Microsoft.AspNetCore.Authorization.Authorize(Policy = AuthNPolicies.Public)]
	public async Task Register(RegisterRequest request)
	{
		var outcome = await registerHandler.Handle(request, httpContextAccessor.HttpContext!.RequestAborted).ConfigureAwait(false);
		if (outcome.TryGetValue(out Failed failed))
			throw failed.Problem.ToRpcException();
	}

	/// <inheritdoc />
	[Microsoft.AspNetCore.Authorization.Authorize(Policy = AuthNPolicies.Public)]
	public async Task<LogoutResult> Logout(LogoutRequest request)
	{
		var outcome = await logoutHandler.Handle(request, httpContextAccessor.HttpContext!.RequestAborted).ConfigureAwait(false);
		return outcome switch
		{
			Success<Unit> => new LogoutResult { DeferredCompletionUrl = TryGetDeferredCompletionUrl() },
			Failed(var problem) => throw problem.ToRpcException(),
		};
	}

	string? TryGetDeferredCompletionUrl()
	{
		// Only ever set on the Blazor-Server in-process path (a circuit that couldn't Set-Cookie
		// because the response had already started) — a real gRPC/WASM call never stashes this, so
		// this naturally returns null there without any channel-specific branching.
		if (httpContextAccessor.HttpContext!.Items[NorseSignInManager.DeferredSignInKeyItemName] is not string key)
			return null;

		return $"{DeferredSignInEndpointRouteBuilderExtensions.DefaultPattern}?key={Uri.EscapeDataString(key)}&returnUrl={Uri.EscapeDataString("/")}";
	}
}
