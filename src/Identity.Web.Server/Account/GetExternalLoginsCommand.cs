using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.Account;

/// <summary>
///     The server-sovereign mediator identity for the request-less <see cref="IAccountService.GetExternalLogins" /> operation, carried over <see cref="Unit" /> (the <see cref="LogoutCommand" /> shape), gated to the self-service account tier. See
///     <see cref="LoginCommand" />'s remark.
/// </summary>
[Authorize(Policy = AuthNPolicies.Account)]
sealed record GetExternalLoginsCommand(Unit Request) : CommandRequest<Unit, ExternalLoginsResponse>(Request);
