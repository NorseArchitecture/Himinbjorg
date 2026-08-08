using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server;

/// <summary>
/// The reference backend for Heimdall's <see cref="IAuthenticationService"/> contract — Himinbjörg
/// owns this because it needs EF/Identity access, not because it's the only legal implementation.
/// Pure hydrate-and-send: each method wraps the incoming pure wire DTO in its server-sovereign
/// command (<see cref="LoginCommand"/>/<see cref="RegisterCommand"/>/<see cref="LogoutCommand"/>,
/// Asgard's <c>CommandRequest&lt;TRequest,TResponse&gt;</c>) and sends it through Midgard's
/// four-stage pipeline (validation, authorization, telemetry, exception translation) via Asgard's
/// <see cref="ISender"/> — the command's <c>TResponse</c> <em>is</em> the wire result type, so
/// egress is pure passthrough, no mapping switch. Himinbjörg stays Midgard-blind: it depends only
/// on Asgard's mediator contracts, never on Midgard's pipeline implementation. The one throw point
/// in the whole chain is the gRPC server interceptor (Midgard's <c>OutcomeServerInterceptor</c>),
/// pattern-matching the returned envelope at the transport boundary, never here. Public: Yggdrasil's
/// composition root maps this type directly.
///
/// <c>[Authorize]</c> is mirrored from the interface onto every method here deliberately, not
/// redundantly — ASP.NET Core's gRPC endpoint metadata is gathered by reflecting on this concrete
/// runtime type, not the interface it implements; an interface method's attributes are not visible
/// to that discovery. Without this mirror, decided law item 4's "enforced on every channel" claim is
/// false for the wire channel specifically, even though the command wrapper declares the policy
/// correctly for the mediator pipeline's own <c>AuthorizationBehavior</c>.
/// </summary>
public sealed class AuthenticationService(ISender sender) : IAuthenticationService
{
	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Public)]
	public Task<Outcome<NavigationResult>> Login(LoginRequest request, CancellationToken cancellationToken = default) =>
		sender.Send(new LoginCommand(request), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Public)]
	public Task<Outcome<NavigationResult>> Register(RegisterRequest request, CancellationToken cancellationToken = default) =>
		sender.Send(new RegisterCommand(request), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Public)]
	public Task<Outcome<NavigationResult>> Logout(CancellationToken cancellationToken = default) =>
		sender.Send(new LogoutCommand(Unit.Value), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Public)]
	public Task<Outcome<BoolResponse>> EmailExists(EmailExistsRequest request, CancellationToken cancellationToken = default) =>
		sender.Send(new EmailExistsCommand(request), cancellationToken).AsTask();
}
