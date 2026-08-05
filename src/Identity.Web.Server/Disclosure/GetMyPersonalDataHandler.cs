using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
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
/// principal's <see cref="ClaimTypes.NameIdentifier"/> claim, never the request.
/// </summary>
/// <remarks>
/// <see cref="ClaimTypes.NameIdentifier"/> is hardcoded rather than resolved through
/// <c>IOptions&lt;IdentityOptions&gt;.Value.ClaimsIdentity.UserIdClaimType</c> -- a deliberate
/// simplification, not an oversight: nothing in this realm ever configures that option away from
/// its ASP.NET Core Identity default (see <c>IdentityBuilderExtensions.AddNorseIdentity</c>, which
/// only ever touches <c>Stores.SchemaVersion</c>/<c>Stores.ProtectPersonalData</c>), so hardcoding
/// is safe and keeps this handler's constructor to exactly the two dependencies its tests exercise
/// rather than adding a third (<c>IOptions&lt;IdentityOptions&gt;</c>) purely to re-derive a value
/// that never varies. A live principal with no backing row is data drift, not a legitimate
/// post-shred state -- a shredded user's session dies at the next revalidation (see
/// <see cref="NorseSignInManager"/>), it never reaches this handler with a stale principal -- so a
/// missing row answers <see cref="ErrorCategory.NotFound"/>, same honest answer the masked handler
/// gives an unknown subject.
/// </remarks>
sealed class GetMyPersonalDataHandler(NorseIdentityDbContext context, IPrincipalAccessor principalAccessor) :
	IRequestHandler<GetMyPersonalDataCommand, PersonalDataResponse>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<PersonalDataResponse>> Handle(GetMyPersonalDataCommand request, CancellationToken cancellationToken = default)
	{
		var principal = await principalAccessor.GetPrincipalAsync(cancellationToken).ConfigureAwait(false);
		var subjectId = Guid.Parse(principal.FindFirstValue(ClaimTypes.NameIdentifier)!);

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
