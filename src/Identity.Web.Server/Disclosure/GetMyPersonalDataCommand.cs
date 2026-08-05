using Microsoft.AspNetCore.Authorization;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server.Disclosure;

/// <summary>
/// The server-sovereign mediator identity for Heimdall's empty <see cref="GetMyPersonalDataRequest"/>
/// wire DTO -- a one-line wrapper carrying no fields of its own beyond the (empty) wrapped request,
/// giving it an <c>[Authorize]</c> policy and a unique handler binding without the wire type itself
/// ever touching the mediator. See <see cref="LoginCommand"/>'s remark.
/// </summary>
[Authorize(Policy = IdentityPolicies.Self)]
sealed record GetMyPersonalDataCommand(GetMyPersonalDataRequest Request) :
	CommandRequest<GetMyPersonalDataRequest, PersonalDataResponse>(Request);
