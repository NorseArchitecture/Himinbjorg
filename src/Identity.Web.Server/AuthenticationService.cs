using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.DeferredSignIn;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Primitives;

namespace Norse.Identity.Web.Server;

/// <summary>
/// The reference backend for Heimdall's <see cref="IAuthenticationService"/> contract — Himinbjörg
/// owns this because it needs EF/Identity access, not because it's the only legal implementation.
/// Trivially thin by design (spec §9, 2026-07-24 amendment to decided law item 3): every method
/// sends its request through Midgard's four-stage pipeline (validation, authorization, telemetry,
/// exception translation) via Asgard's <see cref="ISender"/> and returns the resulting
/// <see cref="Outcome{T}"/> as data — zero throw statements, zero <c>RpcException</c>. Himinbjörg
/// stays Midgard-blind: it depends only on Asgard's mediator contracts, never on Midgard's pipeline
/// implementation. The one throw point in the whole chain is the gRPC server interceptor (Midgard's
/// <c>OutcomeServerInterceptor</c>), pattern-matching the returned envelope at the transport
/// boundary, never here. Public: Yggdrasil's composition root maps this type directly.
///
/// <c>[Authorize]</c> is mirrored from the interface onto every method here deliberately, not
/// redundantly — ASP.NET Core's gRPC endpoint metadata is gathered by reflecting on this concrete
/// runtime type, not the interface it implements; an interface method's attributes are not visible
/// to that discovery. Without this mirror, decided law item 4's "enforced on every channel" claim is
/// false for the wire channel specifically, even though the interface declares the policy correctly
/// (spec Remand 3, 2026-07-24 review).
/// </summary>
public sealed class AuthenticationService(
	ISender sender,
	IDeferredSignIn deferredSignIn,
	IHttpContextAccessor httpContextAccessor)
	: IAuthenticationService
{
	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Public)]
	public async Task<Outcome<LoginResult>> Login(LoginRequest request, CancellationToken cancellationToken = default)
	{
		var outcome = await sender.Send(request, cancellationToken).ConfigureAwait(false);
		return outcome switch
		{
			Success<BoolResponse>(var value) => Outcome<LoginResult>.Ok(new LoginResult { Succeeded = value.Value, DeferredCompletionUrl = TryGetDeferredCompletionUrl() }),
			Failed(var problem) => new Outcome<LoginResult>(new Failed(problem)),
		};
	}

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Public)]
	public async Task<Outcome<Unit>> Register(RegisterRequest request, CancellationToken cancellationToken = default)
	{
		var outcome = await sender.Send(request, cancellationToken).ConfigureAwait(false);
		return outcome switch
		{
			Success<BoolResponse> => Outcome<Unit>.Ok(Unit.Value),
			Failed(var problem) => new Outcome<Unit>(new Failed(problem)),
		};
	}

	/// <inheritdoc />
	[Microsoft.AspNetCore.Authorization.Authorize(Policy = AuthNPolicies.Public)]
	public async Task<Outcome<LogoutResult>> Logout(LogoutRequest request, CancellationToken cancellationToken = default)
	{
		var outcome = await sender.Send(request, cancellationToken).ConfigureAwait(false);
		return outcome switch
		{
			Success<Unit> => Outcome<LogoutResult>.Ok(new LogoutResult { DeferredCompletionUrl = TryGetDeferredCompletionUrl() }),
			Failed(var problem) => new Outcome<LogoutResult>(new Failed(problem)),
		};
	}

	string? TryGetDeferredCompletionUrl()
	{
		// Only ever set on the Blazor-Server in-process path (a circuit that couldn't Set-Cookie
		// because the response had already started) — a real gRPC/WASM call never stashes this, so
		// this naturally returns null there without any channel-specific branching.
		if (httpContextAccessor.HttpContext!.Items[NorseSignInManager.DeferredSignInKeyItemName] is not string key)
			return null;

		return deferredSignIn.BuildCompletionUrl(key, "/");
	}
}
