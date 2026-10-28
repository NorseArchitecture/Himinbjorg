using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.Web.Server.Account;

namespace Norse.Identity.Web.Server.Passkeys;

/// <summary>
///     The server-sovereign mediator identity for the request-less <see cref="IPasskeyService.GetPasskeys" /> operation, carried over <see cref="Unit" /> (the <see cref="GetAccountStatusCommand" /> shape), gated to the self-service account tier. See
///     <see cref="LoginCommand" />'s remark.
/// </summary>
[Authorize(Policy = AuthNPolicies.Account)]
sealed record GetPasskeysCommand(Unit Request) : CommandRequest<Unit, PasskeysResponse>(Request);
