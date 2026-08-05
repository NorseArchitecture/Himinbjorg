using Microsoft.EntityFrameworkCore;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server;

/// <summary>
/// The shred ceremony, three acts in law order (2026-08-03 PII spec §4.2): null the current-row
/// lookup hashes, rotate the security stamp (arming <c>SecurityStampValidator</c> to kill live
/// sessions within one revalidation interval), destroy the per-subject wrapping key. Database acts
/// commit before the destruction. Partial-failure contract: a failure in acts 1-2 aborts with the
/// key intact and the row untouched-or-not per the single UPDATE's atomicity; a failure in act 3
/// leaves a <b>half-severed, retryable</b> state -- hashes nulled, stamp rotated, sessions dying,
/// key intact, no receipt. The re-run matches the row again, re-rotates harmlessly, and completes
/// the destruction; retry-until-receipt is the caller's obligation (recorded as the future Syn DSAR
/// machinery's contract). Payload ciphertext stays in place, dark. This is the ceremony, not the
/// trigger.
/// </summary>
public sealed class ErasureService(NorseIdentityDbContext context, ISubjectKeyStore keyStore)
{
	/// <summary>Severs the subject. NotFound when no row exists -- no key is burned for a ghost.</summary>
	public async Task<Outcome<ErasureReceipt>> ShredAsync(Guid subjectId, CancellationToken cancellationToken = default)
	{
		// NorseUser.SecurityStamp is a plain HasMaxLength(32) column (see NorseUser.Configure) --
		// UserManager<TUser>.NewSecurityStamp() is Base32.GenerateBase32(), never Guid-shaped, so
		// IdentityValueConverters.Stamp (a string<->Guid converter) does NOT ride this column --
		// that converter is wired to ConcurrencyStamp only. The rotation value must therefore just
		// fit the 32-character column, not round-trip a converter that isn't there: Guid "N" format
		// is exactly 32 hex characters with no separators; "D" format (36 characters, with dashes)
		// overflows the column and Postgres rejects the write outright.
		var stamp = Guid.NewGuid().ToString("N");
		var updated = await context.Users
			.Where(u => u.Id == subjectId)
			.ExecuteUpdateAsync(setters => setters
				.SetProperty(u => u.NormalizedUserName, (string?)null)
				.SetProperty(u => u.NormalizedEmail, (string?)null)
				.SetProperty(u => u.SecurityStamp, stamp), cancellationToken)
			.ConfigureAwait(false);
		if (updated == 0)
			return Outcome<ErasureReceipt>.Err(ErrorCategory.NotFound);
		var receipt = await keyStore.DestroyAsync(subjectId, cancellationToken).ConfigureAwait(false);
		return Outcome<ErasureReceipt>.Ok(receipt);
	}
}
