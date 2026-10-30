using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.Account;

/// <summary>
///     The server-sovereign mediator identity for the request-less <see cref="IAccountService.GetAccountStatus" /> operation, carried over <see cref="Unit" /> (the <see cref="LogoutCommand" /> shape), gated to the read-only account tier, which a user bearer for <c>Norse.User</c> reaches as well as the cookie (2026-10-29 OpenIddict spec §7.5). See
///     <see cref="LoginCommand" />'s remark.
/// </summary>
[Authorize(Policy = AuthNPolicies.AccountRead)]
sealed record GetAccountStatusCommand(Unit Request) : CommandRequest<Unit, AccountStatusResponse>(Request);
