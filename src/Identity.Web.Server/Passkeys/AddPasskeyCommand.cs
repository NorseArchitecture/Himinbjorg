using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Components.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.Passkeys;

/// <summary>
///     The server-sovereign mediator identity for Heimdall's pure <see cref="AddPasskeyRequest" /> wire DTO, gated to the self-service account tier and to a recent authentication, whose hop lands back on <c>/Account/Manage/Passkeys</c> (2026-10-29 OpenIddict spec §6.3, T4-4). See
///     <see cref="LoginCommand" />'s remark.
/// </summary>
[Authorize(Policy = AuthNPolicies.Account)]
[Authorize(Policy = NorsePolicies.RecentAuthentication)]
[ReauthenticationLanding("/Account/Manage/Passkeys")]
sealed record AddPasskeyCommand(AddPasskeyRequest Request) : CommandRequest<AddPasskeyRequest, NavigationResult>(Request);
