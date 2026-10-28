using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.Account;

/// <summary>
///     The server-sovereign mediator identity for Heimdall's pure <see cref="SetPasswordRequest" /> wire DTO, gated to the self-service account tier. See
///     <see cref="LoginCommand" />'s remark.
/// </summary>
[Authorize(Policy = AuthNPolicies.Account)]
sealed record SetPasswordCommand(SetPasswordRequest Request) : CommandRequest<SetPasswordRequest, NavigationResult>(Request);
