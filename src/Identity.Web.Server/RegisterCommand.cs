using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server;

/// <summary>The server-sovereign mediator identity for Heimdall's pure <see cref="RegisterRequest"/> wire DTO. See <see cref="LoginCommand"/>'s remark.</summary>
[Authorize(Policy = AuthNPolicies.Public)]
sealed record RegisterCommand(RegisterRequest Request) : CommandRequest<RegisterRequest, RegisterResult>(Request);
