using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server;

/// <summary>
/// The server-sovereign mediator identity for Heimdall's <c>Logout</c> operation — wraps
/// <see cref="Unit"/> rather than a wire DTO because the wire operation is
/// <see cref="CancellationToken"/>-only (spike-verified: protobuf-net.Grpc needs no request message
/// for a unary call). No wire validator exists for <see cref="Unit"/>, so the generated
/// <see cref="CommandRequestValidator{TCommand,TRequest,TResponse}"/> adapter still gets registered
/// uniformly, resolving zero child validators — an empty collection is a valid command by
/// definition, absence is a pass.
/// </summary>
[Authorize(Policy = AuthNPolicies.Public)]
sealed record LogoutCommand(Unit Request) : CommandRequest<Unit, LogoutResult>(Request);
