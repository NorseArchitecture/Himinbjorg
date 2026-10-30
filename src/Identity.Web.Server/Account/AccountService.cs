using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.Account;

/// <summary>
///     The reference backend for Heimdall's <see cref="IAccountService" /> self-service contract. Pure
///     hydrate-and-send, the <see cref="AuthenticationService" /> shape: each method wraps the incoming wire request
///     (or <see cref="Unit" />, for the two request-less reads) in its server-sovereign command and sends it through
///     Midgard's pipeline via Asgard's <see cref="ISender" />; the command's <c>TResponse</c> <em>is</em> the wire
///     result type, so egress is pure passthrough. <c>[Authorize]</c> is mirrored from the command wrappers onto every
///     method here deliberately: ASP.NET Core's gRPC endpoint metadata is gathered by reflecting on this concrete type,
///     never the interface. Each method mirrors its command's operation policy alone: the account tier, or the read-only
///     <see cref="AuthNPolicies.AccountRead" /> for <see cref="GetAccountStatus" />; no class-level <c>[Authorize]</c>, which
///     would combine with every method's. Public: Yggdrasil's composition root maps this type directly.
/// </summary>
/// <param name="sender">Sends each command through the mediator pipeline.</param>
public sealed class AccountService(ISender sender) : IAccountService
{
	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.AccountRead)]
	public Task<Outcome<AccountStatusResponse>> GetAccountStatus(CancellationToken cancellationToken = default) =>
		sender.Send(new GetAccountStatusCommand(Unit.Value), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<NavigationResult>> SetPhoneNumber(SetPhoneNumberRequest request,
		CancellationToken cancellationToken = default) =>
		sender.Send(new SetPhoneNumberCommand(request), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<NavigationResult>> ChangePassword(ChangePasswordRequest request,
		CancellationToken cancellationToken = default) =>
		sender.Send(new ChangePasswordCommand(request), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<NavigationResult>> SetPassword(SetPasswordRequest request,
		CancellationToken cancellationToken = default) =>
		sender.Send(new SetPasswordCommand(request), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<BoolResponse>> ChangeEmail(ChangeEmailRequest request,
		CancellationToken cancellationToken = default) =>
		sender.Send(new ChangeEmailCommand(request), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<ExternalLoginsResponse>> GetExternalLogins(CancellationToken cancellationToken = default) =>
		sender.Send(new GetExternalLoginsCommand(Unit.Value), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<NavigationResult>> RemoveExternalLogin(RemoveExternalLoginRequest request,
		CancellationToken cancellationToken = default) =>
		sender.Send(new RemoveExternalLoginCommand(request), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Account)]
	public Task<Outcome<NavigationResult>> DeletePersonalData(DeletePersonalDataRequest request,
		CancellationToken cancellationToken = default) =>
		sender.Send(new DeletePersonalDataCommand(request), cancellationToken).AsTask();
}
