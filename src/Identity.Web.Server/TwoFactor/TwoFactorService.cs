using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.TwoFactor;

/// <summary>
///     The reference backend for Heimdall's <see cref="ITwoFactorService" /> two-factor contract.
///     Pure hydrate-and-send, the <see cref="Account.AccountService" /> shape: each method wraps the incoming wire
///     request (or <see cref="Unit" />, for the request-less operations) in its server-sovereign command and sends it
///     through Midgard's pipeline via Asgard's <see cref="ISender" />; the command's <c>TResponse</c> <em>is</em> the
///     wire result type, so egress is pure passthrough. <c>[Authorize]</c> is mirrored from the command wrappers onto
///     every method here deliberately: ASP.NET Core's gRPC endpoint metadata is gathered by reflecting on this
///     concrete type, never the interface. Only the operation policy is mirrored: the gated commands' freshness
///     (<c>NorsePolicies.RecentAuthentication</c>) rides the command alone, because an endpoint-edge freshness check would
///     refuse a stale caller with a bare 403 before the mediator could author the re-authentication hop (T4-3). Public:
///     Yggdrasil's composition root maps this type directly.
/// </summary>
/// <param name="sender">Sends each command through the mediator pipeline.</param>
public sealed class TwoFactorService(ISender sender) : ITwoFactorService
{
	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<AuthenticatorSetupResponse>> GetAuthenticatorSetup(CancellationToken cancellationToken = default) =>
		sender.Send(new GetAuthenticatorSetupCommand(Unit.Value), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<NavigationResult>> EnableAuthenticator(EnableAuthenticatorRequest request,
		CancellationToken cancellationToken = default) =>
		sender.Send(new EnableAuthenticatorCommand(request), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<RecoveryCodesResponse>> RevealRecoveryCodes(RevealRecoveryCodesRequest request,
		CancellationToken cancellationToken = default) =>
		sender.Send(new RevealRecoveryCodesCommand(request), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<NavigationResult>> ResetAuthenticator(CancellationToken cancellationToken = default) =>
		sender.Send(new ResetAuthenticatorCommand(Unit.Value), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<NavigationResult>> DisableTwoFactor(CancellationToken cancellationToken = default) =>
		sender.Send(new DisableTwoFactorCommand(Unit.Value), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<RecoveryCodesResponse>> GenerateRecoveryCodes(CancellationToken cancellationToken = default) =>
		sender.Send(new GenerateRecoveryCodesCommand(Unit.Value), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<NavigationResult>> ForgetTwoFactorClient(CancellationToken cancellationToken = default) =>
		sender.Send(new ForgetTwoFactorClientCommand(Unit.Value), cancellationToken).AsTask();
}
