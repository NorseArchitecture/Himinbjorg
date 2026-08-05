using Microsoft.EntityFrameworkCore;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Primitives;
using Norse.Primitives.Pii;

namespace Norse.Identity.Web.Server.Disclosure;

/// <summary>
/// The masked-disclosure query handler (2026-08-03 PII spec §6): a second party's personal data,
/// masked at the source through the PII structs' own <see cref="IMaskedValue.Masked"/> law -- the
/// endpoint never authors a mask by hand.
/// </summary>
sealed class GetMaskedPersonalDataHandler(NorseIdentityDbContext context) :
	IRequestHandler<MaskedPersonalDataCommand, MaskedPersonalDataResponse>
{
	/// <inheritdoc />
	public async ValueTask<Outcome<MaskedPersonalDataResponse>> Handle(MaskedPersonalDataCommand request, CancellationToken cancellationToken = default)
	{
		// The repository fold (spec §3.1): KeyDestroyedException answers Erased with the receipt;
		// KeyMissingException is deliberately left to escape to ExceptionTranslationBehavior -- an
		// incident, never confused with erasure. Both queries are single-subject by construction
		// (spec §4.1) -- this try/catch is the whole fold.
		try
		{
			var row = await context.Users.AsNoTracking()
				.Where(u => u.Id == request.Request.SubjectId)
				.Select(u => new { u.Email, u.PhoneNumber })
				.SingleOrDefaultAsync(cancellationToken).ConfigureAwait(false);
			if (row is null)
				return Outcome<MaskedPersonalDataResponse>.Err(ErrorCategory.NotFound);
			return Outcome<MaskedPersonalDataResponse>.Ok(new()
			{
				Email = row.Email is { Length: > 0 } email ? Mask<EmailAddress>(email) : "",
				PhoneNumber = row.PhoneNumber is { Length: > 0 } phone ? Mask<PhoneNumber>(phone) : ""
			});
		}
		catch (KeyDestroyedException e)
		{
			return new(new Failed(new Problem { Category = ErrorCategory.Erased, Receipt = e.Receipt }));
		}
	}

	// Masks through the struct's own law, never by hand: a parse failure of already-decrypted data
	// is storage corruption, not user input -- let it throw (InvalidOperationException -> Fault).
	static string Mask<TPii>(string? wire) where TPii : struct, IPiiScalar<TPii> =>
		TPii.Parse(wire).TryGetValue(out Success<TPii> success) ?
			success.Value.Masked :
			throw new InvalidOperationException($"Decrypted {typeof(TPii).Name} no longer parses -- storage corruption.");
}
