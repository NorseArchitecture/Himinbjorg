using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server;

/// <summary>
/// The server-sovereign mediator identity for Heimdall's pure <see cref="LoginRequest"/> wire DTO —
/// a one-line wrapper carrying no fields of its own, giving the wire record an <c>[Authorize]</c>
/// policy and a unique handler binding without either ever touching the wire type itself.
/// <see cref="AuthenticationService"/> hydrates one of these around the incoming
/// <see cref="LoginRequest"/> and sends it; Heimdall's <c>LoginRequestValidator</c> still validates
/// the wrapped request directly, reached through the generated
/// <see cref="CommandRequestValidator{TCommand,TRequest,TResponse}"/> adapter.
/// </summary>
[Authorize(Policy = AuthNPolicies.Public)]
sealed record LoginCommand(LoginRequest Request) : CommandRequest<LoginRequest, NavigationResult>(Request);
