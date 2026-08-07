using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server;

/// <summary>The server-sovereign mediator identity for Heimdall's pure <see cref="EmailExistsRequest"/> wire DTO. See <see cref="LoginCommand"/>'s remark.</summary>
[Authorize(Policy = AuthNPolicies.Public)]
sealed record EmailExistsCommand(EmailExistsRequest Request) : CommandRequest<EmailExistsRequest, BoolResponse>(Request);
