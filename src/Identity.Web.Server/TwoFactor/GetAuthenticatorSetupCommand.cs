using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Components.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.Web.Server.Account;

namespace Norse.Identity.Web.Server.TwoFactor;

/// <summary>
///     The server-sovereign mediator identity for the request-less <see cref="ITwoFactorService.GetAuthenticatorSetup" /> operation, carried over <see cref="Unit" /> (the <see cref="GetAccountStatusCommand" /> shape), gated to the self-service account tier and to a recent authentication, whose hop lands back on <c>/Account/Manage/EnableAuthenticator</c> (2026-10-29 OpenIddict spec §6.3, T4-4). See
///     <see cref="LoginCommand" />'s remark.
/// </summary>
[Authorize(Policy = AuthNPolicies.Account)]
[Authorize(Policy = NorsePolicies.RecentAuthentication)]
[ReauthenticationLanding("/Account/Manage/EnableAuthenticator")]
sealed record GetAuthenticatorSetupCommand(Unit Request) : CommandRequest<Unit, AuthenticatorSetupResponse>(Request);
