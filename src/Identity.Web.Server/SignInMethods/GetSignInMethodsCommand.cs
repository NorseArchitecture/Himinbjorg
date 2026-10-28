using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.SignInMethods;

/// <summary>
///     The server-sovereign mediator identity for Heimdall's pure <see cref="GetSignInMethodsRequest" /> wire DTO, gated to the public tier. See
///     <see cref="LoginCommand" />'s remark.
/// </summary>
[Authorize(Policy = AuthNPolicies.Public)]
sealed record GetSignInMethodsCommand(GetSignInMethodsRequest Request) : CommandRequest<GetSignInMethodsRequest, SignInMethodsResponse>(Request);
