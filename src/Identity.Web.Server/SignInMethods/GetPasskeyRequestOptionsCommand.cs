using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.Web.Server.Account;

namespace Norse.Identity.Web.Server.SignInMethods;

/// <summary>
///     The server-sovereign mediator identity for the request-less <see cref="ISignInMethodsService.GetPasskeyRequestOptions" /> operation, carried over <see cref="Unit" /> (the <see cref="GetAccountStatusCommand" /> shape), gated to the public tier. See
///     <see cref="LoginCommand" />'s remark.
/// </summary>
[Authorize(Policy = AuthNPolicies.Public)]
sealed record GetPasskeyRequestOptionsCommand(Unit Request) : CommandRequest<Unit, PasskeyRequestOptionsResponse>(Request);
