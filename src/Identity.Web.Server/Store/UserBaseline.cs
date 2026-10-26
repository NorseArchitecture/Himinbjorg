using System.Collections.Immutable;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Store;

/// <summary>
///     The as-read baseline of one <see cref="NorseUser" /> instance (2026-10-24 explicit-writes spec §4.2): the
///     plaintext of every mapped scalar column as it came out of the database, after the converters decrypted it,
///     plus the <see cref="ConcurrencyStamp" /> it was read with and the sign count of every passkey the store
///     returned for that user. Ciphertext can't detect change (a fresh nonce per encryption) and the manager mutates
///     the instance before it updates, so this snapshot is the only source of the original values a guarded write
///     needs.
/// </summary>
/// <remarks>
///     A value, never an identity map: it holds no key lookup, no graph and no navigation, and nothing detects
///     change automatically. <see cref="NorseUserStore" /> attaches one to each instance it hands out.
/// </remarks>
sealed record UserBaseline
{
	/// <summary>The decrypted <c>UserName</c>.</summary>
	public required string? UserName { get; init; }

	/// <summary>The <c>NormalizedUserName</c> blind index.</summary>
	public required string? NormalizedUserName { get; init; }

	/// <summary>The decrypted <c>Email</c>.</summary>
	public required string? Email { get; init; }

	/// <summary>The <c>NormalizedEmail</c> blind index.</summary>
	public required string? NormalizedEmail { get; init; }

	/// <summary>The <c>EmailConfirmed</c> flag.</summary>
	public required bool EmailConfirmed { get; init; }

	/// <summary>The <c>PasswordHash</c>.</summary>
	public required string? PasswordHash { get; init; }

	/// <summary>The <c>SecurityStamp</c>.</summary>
	public required string? SecurityStamp { get; init; }

	/// <summary>The <c>ConcurrencyStamp</c> the instance was read with.</summary>
	public required string? ConcurrencyStamp { get; init; }

	/// <summary>The decrypted <c>PhoneNumber</c>.</summary>
	public required string? PhoneNumber { get; init; }

	/// <summary>The <c>PhoneNumberConfirmed</c> flag.</summary>
	public required bool PhoneNumberConfirmed { get; init; }

	/// <summary>The <c>TwoFactorEnabled</c> flag.</summary>
	public required bool TwoFactorEnabled { get; init; }

	/// <summary>The <c>LockoutEnd</c>.</summary>
	public required DateTimeOffset? LockoutEnd { get; init; }

	/// <summary>The <c>LockoutEnabled</c> flag.</summary>
	public required bool LockoutEnabled { get; init; }

	/// <summary>The <c>AccessFailedCount</c>.</summary>
	public required int AccessFailedCount { get; init; }

	/// <summary>The as-read sign count of each passkey the store returned, keyed by its base64 credential id.</summary>
	ImmutableDictionary<string, uint> PasskeySignCounts { get; init; } = [];

	/// <summary>Snapshots <paramref name="user" />'s current scalar values, with no passkey state.</summary>
	/// <param name="user">The instance as it was just read or inserted.</param>
	public static UserBaseline Capture(NorseUser user) =>
		new()
		{
			UserName = user.UserName,
			NormalizedUserName = user.NormalizedUserName,
			Email = user.Email,
			NormalizedEmail = user.NormalizedEmail,
			EmailConfirmed = user.EmailConfirmed,
			PasswordHash = user.PasswordHash,
			SecurityStamp = user.SecurityStamp,
			ConcurrencyStamp = user.ConcurrencyStamp,
			PhoneNumber = user.PhoneNumber,
			PhoneNumberConfirmed = user.PhoneNumberConfirmed,
			TwoFactorEnabled = user.TwoFactorEnabled,
			LockoutEnd = user.LockoutEnd,
			LockoutEnabled = user.LockoutEnabled,
			AccessFailedCount = user.AccessFailedCount
		};

	/// <summary>
	///     The baseline after a successful flush (spec §4.2): <paramref name="user" />'s values as just committed,
	///     with the new stamp, keeping the as-read passkey state, which the flush did not touch.
	/// </summary>
	/// <param name="user">The instance whose flush just committed.</param>
	public UserBaseline Refreshed(NorseUser user) =>
		Capture(user) with { PasskeySignCounts = PasskeySignCounts };

	/// <summary>
	///     Puts every mapped scalar of <paramref name="user" />, and its stamp, back to this baseline (spec §4.8): a
	///     failed operation leaves the instance exactly as read.
	/// </summary>
	/// <param name="user">The instance whose operation failed.</param>
	public void Restore(NorseUser user)
	{
		user.UserName = UserName;
		user.NormalizedUserName = NormalizedUserName;
		user.Email = Email;
		user.NormalizedEmail = NormalizedEmail;
		user.EmailConfirmed = EmailConfirmed;
		user.PasswordHash = PasswordHash;
		user.SecurityStamp = SecurityStamp;
		user.ConcurrencyStamp = ConcurrencyStamp;
		user.PhoneNumber = PhoneNumber;
		user.PhoneNumberConfirmed = PhoneNumberConfirmed;
		user.TwoFactorEnabled = TwoFactorEnabled;
		user.LockoutEnd = LockoutEnd;
		user.LockoutEnabled = LockoutEnabled;
		user.AccessFailedCount = AccessFailedCount;
	}

	/// <summary>This baseline, plus the as-read sign count of each of <paramref name="passkeys" />.</summary>
	/// <param name="passkeys">The passkeys exactly as the store just read them for this user.</param>
	public UserBaseline WithPasskeys(IEnumerable<NorseUserPasskey> passkeys) =>
		this with
		{
			PasskeySignCounts = PasskeySignCounts.SetItems(passkeys.Select(static passkey =>
				KeyValuePair.Create(Convert.ToBase64String(passkey.CredentialId), passkey.Data.SignCount)))
		};

	/// <summary>
	///     This baseline after a committed flush's passkey intents (spec §4.2): an enrollment or an assertion update
	///     records the count it committed, and a removal forgets the credential.
	/// </summary>
	/// <param name="intents">The intents the flush just committed.</param>
	public UserBaseline WithPasskeyIntents(IEnumerable<StagedIntent> intents) =>
		intents.Aggregate(this, static (baseline, intent) => intent switch
		{
			StagedIntent.EnrollPasskey enroll => baseline with
			{
				PasskeySignCounts = baseline.PasskeySignCounts.SetItem(Convert.ToBase64String(enroll.CredentialId), enroll.Data.SignCount)
			},
			StagedIntent.UpdatePasskey update => baseline with
			{
				PasskeySignCounts = baseline.PasskeySignCounts.SetItem(Convert.ToBase64String(update.CredentialId), update.SignCount)
			},
			StagedIntent.RemovePasskey remove => baseline with
			{
				PasskeySignCounts = baseline.PasskeySignCounts.Remove(Convert.ToBase64String(remove.CredentialId))
			},
			_ => baseline
		});

	/// <summary>
	///     The as-read sign count of the passkey <paramref name="credentialId" />, or <see langword="null" /> when the
	///     store never returned it for this user.
	/// </summary>
	/// <param name="credentialId">The passkey's credential id.</param>
	public uint? PasskeySignCount(byte[] credentialId) =>
		PasskeySignCounts.TryGetValue(Convert.ToBase64String(credentialId), out var signCount) ?
			signCount :
			null;
}
