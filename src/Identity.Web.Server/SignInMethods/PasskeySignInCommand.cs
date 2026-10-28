using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.SignInMethods;

/// <summary>
///     The server-sovereign mediator identity for Heimdall's pure <see cref="PasskeySignInRequest" /> wire DTO, gated to the public tier. See
///     <see cref="LoginCommand" />'s remark.
/// </summary>
[Authorize(Policy = AuthNPolicies.Public)]
sealed record PasskeySignInCommand(PasskeySignInRequest Request) : CommandRequest<PasskeySignInRequest, NavigationResult>(Request);
