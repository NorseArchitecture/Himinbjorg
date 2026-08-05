using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Disclosure;

/// <summary>
/// The self-disclosure query handler (2026-08-03 PII spec §6.1): the caller's own personal data,
/// full and unmasked -- there is no subject-id parameter anywhere on this path, the authenticated
/// principal is the only subject this handler can ever disclose. Subject id comes from the
/// principal's <c>Options.ClaimsIdentity.UserIdClaimType</c> claim, never the request.
/// </summary>
/// <remarks>
/// The claim type is read from <see cref="IOptions{TOptions}"/> of <see cref="IdentityOptions"/>,
/// not hardcoded to <see cref="System.Security.Claims.ClaimTypes.NameIdentifier"/> -- this is the
/// exact same option <see cref="NorseUserClaimsPrincipalFactory"/> (same assembly) allowlists the
/// principal's claims against; hardcoding here would let the two halves of one contract silently
/// disagree the moment either one changes. A live principal with no backing row is data drift, not
/// a legitimate post-shred state -- a shredded user's session dies at the next revalidation (see
/// <see cref="NorseSignInManager"/>), it never reaches this handler with a stale principal -- so a
/// missing row answers <see cref="ErrorCategory.NotFound"/>, same honest answer the masked handler
/// gives an unknown subject.
/// </remarks>
sealed class GetMyPersonalDataHandler(NorseIdentityDbContext context, IPrincipalAccessor principalAccessor, IOptions<IdentityOptions> options) :
	IRequestHandler<GetMyPersonalDataCommand, PersonalDataResponse>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<PersonalDataResponse>> Handle(GetMyPersonalDataCommand request, CancellationToken cancellationToken = default)
	{
		var principal = await principalAccessor.GetPrincipalAsync(cancellationToken).ConfigureAwait(false);
		var claimType = options.Value.ClaimsIdentity.UserIdClaimType;
		var claimValue = principal.FindFirstValue(claimType) ??
			throw new InvalidOperationException(
				$"The principal carries no '{claimType}' claim -- GetMyPersonalDataHandler cannot resolve a subject to disclose without it.");
		var subjectId = Guid.TryParse(claimValue, out var parsed) ?
			parsed :
			throw new InvalidOperationException(
				$"The principal's '{claimType}' claim ('{claimValue}') is not a valid Guid.");

		// The repository fold (spec §3.1): KeyDestroyedException answers Erased with the receipt;
		// KeyMissingException is deliberately left to escape to ExceptionTranslationBehavior -- an
		// incident, never confused with erasure.
		try
		{
			var row = await context.Users.AsNoTracking()
				.Where(u => u.Id == subjectId)
				.Select(u => new { u.Email, u.PhoneNumber })
				.SingleOrDefaultAsync(cancellationToken).ConfigureAwait(false);
			if (row is null)
				return Outcome<PersonalDataResponse>.Err(ErrorCategory.NotFound);
			return Outcome<PersonalDataResponse>.Ok(new()
			{
				Email = row.Email ?? "",
				PhoneNumber = row.PhoneNumber ?? ""
			});
		}
		catch (KeyDestroyedException e)
		{
			return new(new Failed(new Problem { Category = ErrorCategory.Erased, Receipt = e.Receipt }));
		}
	}
}
