using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.Disclosure;

/// <summary>
/// The server-sovereign mediator identity for Heimdall's <see cref="GetMaskedPersonalDataRequest"/>
/// wire DTO. See <see cref="LoginCommand"/>'s remark.
/// </summary>
[Authorize(Policy = IdentityPolicies.MaskedDisclosure)]
sealed record MaskedPersonalDataCommand(GetMaskedPersonalDataRequest Request) :
	CommandRequest<GetMaskedPersonalDataRequest, MaskedPersonalDataResponse>(Request);
