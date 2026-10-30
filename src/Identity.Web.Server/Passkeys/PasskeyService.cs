using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.Passkeys;

/// <summary>
///     The reference backend for Heimdall's <see cref="IPasskeyService" /> passkey management contract.
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
public sealed class PasskeyService(ISender sender) : IPasskeyService
{
	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<PasskeysResponse>> GetPasskeys(CancellationToken cancellationToken = default) =>
		sender.Send(new GetPasskeysCommand(Unit.Value), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<PasskeyEntry>> GetPasskey(GetPasskeyRequest request,
		CancellationToken cancellationToken = default) =>
		sender.Send(new GetPasskeyCommand(request), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<PasskeyCreationOptionsResponse>> GetPasskeyCreationOptions(CancellationToken cancellationToken = default) =>
		sender.Send(new GetPasskeyCreationOptionsCommand(Unit.Value), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<NavigationResult>> AddPasskey(AddPasskeyRequest request,
		CancellationToken cancellationToken = default) =>
		sender.Send(new AddPasskeyCommand(request), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<NavigationResult>> RenamePasskey(RenamePasskeyRequest request,
		CancellationToken cancellationToken = default) =>
		sender.Send(new RenamePasskeyCommand(request), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<BoolResponse>> RemovePasskey(RemovePasskeyRequest request,
		CancellationToken cancellationToken = default) =>
		sender.Send(new RemovePasskeyCommand(request), cancellationToken).AsTask();
}
