using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.SignInMethods;

/// <summary>
///     The reference backend for Heimdall's <see cref="ISignInMethodsService" /> anonymous sign-in-method contract.
///     Pure hydrate-and-send, the <see cref="Account.AccountService" /> shape: each method wraps the incoming wire
///     request (or <see cref="Unit" />, for the request-less operations) in its server-sovereign command and sends it
///     through Midgard's pipeline via Asgard's <see cref="ISender" />; the command's <c>TResponse</c> <em>is</em> the
///     wire result type, so egress is pure passthrough. <c>[Authorize]</c> is mirrored from the command wrappers onto
///     every method here deliberately: ASP.NET Core's gRPC endpoint metadata is gathered by reflecting on this
///     concrete type, never the interface. Public: Yggdrasil's composition root maps this type directly.
/// </summary>
/// <param name="sender">Sends each command through the mediator pipeline.</param>
public sealed class SignInMethodsService(ISender sender) : ISignInMethodsService
{
	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Public)]
	public Task<Outcome<SignInMethodsResponse>> GetSignInMethods(GetSignInMethodsRequest request,
		CancellationToken cancellationToken = default) =>
		sender.Send(new GetSignInMethodsCommand(request), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Public)]
	public Task<Outcome<PasskeyRequestOptionsResponse>> GetPasskeyRequestOptions(CancellationToken cancellationToken = default) =>
		sender.Send(new GetPasskeyRequestOptionsCommand(Unit.Value), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = AuthNPolicies.Public)]
	public Task<Outcome<NavigationResult>> PasskeySignIn(PasskeySignInRequest request,
		CancellationToken cancellationToken = default) =>
		sender.Send(new PasskeySignInCommand(request), cancellationToken).AsTask();
}
