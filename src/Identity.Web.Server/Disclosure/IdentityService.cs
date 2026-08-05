using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.Disclosure;

/// <summary>
/// The reference backend for Heimdall's <see cref="IIdentityService"/> disclosure contract --
/// Himinbjörg owns this because it needs EF/Identity access, not because it's the only legal
/// implementation. Pure hydrate-and-send, same shape as <see cref="AuthenticationService"/> and
/// Mímir's <c>ReferenceService</c>: each method wraps the incoming wire request in its
/// server-sovereign command (<see cref="GetMyPersonalDataCommand"/>/<see cref="MaskedPersonalDataCommand"/>)
/// and sends it through Midgard's pipeline via Asgard's <see cref="ISender"/> -- the command's
/// <c>TResponse</c> <em>is</em> the wire result type, so egress is pure passthrough.
///
/// <c>[Authorize]</c> is mirrored from the command wrappers (<see cref="GetMyPersonalDataCommand"/>/
/// <see cref="MaskedPersonalDataCommand"/> carry the real policy) onto every method here deliberately,
/// not redundantly -- ASP.NET Core's gRPC endpoint metadata is gathered by reflecting on this concrete
/// runtime type, not the interface it implements, which carries no <c>[Authorize]</c> at all (wire
/// purity). Public: Yggdrasil's composition root maps this type directly.
/// </summary>
public sealed class IdentityService(ISender sender) : IIdentityService
{
	/// <inheritdoc />
	[Authorize(Policy = IdentityPolicies.Self)]
	public Task<Outcome<PersonalDataResponse>> GetMyPersonalDataAsync(GetMyPersonalDataRequest request, CancellationToken cancellationToken = default) =>
		sender.Send(new GetMyPersonalDataCommand(request), cancellationToken).AsTask();

	/// <inheritdoc />
	[Authorize(Policy = IdentityPolicies.MaskedDisclosure)]
	public Task<Outcome<MaskedPersonalDataResponse>> GetMaskedPersonalDataAsync(GetMaskedPersonalDataRequest request, CancellationToken cancellationToken = default) =>
		sender.Send(new MaskedPersonalDataCommand(request), cancellationToken).AsTask();
}
