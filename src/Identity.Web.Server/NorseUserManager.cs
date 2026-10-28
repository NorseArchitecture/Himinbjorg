using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Norse.Abstractions.Backend.Keys;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;

namespace Norse.Identity.Web.Server;

/// <summary>
///     The one chokepoint every identity write traverses, establishing the ambient crypto subject
///     around the base call so the protector always knows whose DEK to use -- Heimdall and every future
///     caller inherit the scope for free. Create assigns the id first when the caller didn't: the
///     subject must exist before the store encrypts.
/// </summary>
/// <remarks>
///     A failed operation leaves the instance exactly as read (2026-10-24 explicit-writes spec §4.8): every failure
///     out of <see cref="UpdateUserAsync" /> abandons what was staged on the instance, and so does every stock method
///     that can stage and then return early without reaching it (the V5 audit: <see cref="AddToRolesAsync" />,
///     <see cref="RemoveFromRolesAsync" />, and <see cref="ChangeEmailAsync" />'s second token check).
/// </remarks>
public sealed class NorseUserManager(
	IUserStore<NorseUser> store,
	IOptions<IdentityOptions> optionsAccessor,
	IPasswordHasher<NorseUser> passwordHasher,
	IEnumerable<IUserValidator<NorseUser>> userValidators,
	IEnumerable<IPasswordValidator<NorseUser>> passwordValidators,
	ILookupNormalizer keyNormalizer,
	IdentityErrorDescriber errors,
	IServiceProvider services,
	ILogger<UserManager<NorseUser>> logger) :
	UserManager<NorseUser>(store, optionsAccessor, passwordHasher, userValidators, passwordValidators,
		keyNormalizer, errors, services, logger), IRecoveryCodeReplacement, IAuthenticatorKeyProvisioning
{
	/// <summary>The <see cref="IdentityError.Code" /> a refused <c>SetUserNameAsync</c> answers.</summary>
	public const string UserNameIsDerivedErrorCode = NorseIdentityErrorCodes.UserNameIsDerived;

	/// <inheritdoc />
	public override async Task<IdentityResult> CreateAsync(NorseUser user)
	{
		ArgumentNullException.ThrowIfNull(user);
		if (user.Id == Guid.Empty)
			user.Id = Guid.CreateVersion7();
		using (SubjectCryptoScope.Begin(user.Id))
			return await base.CreateAsync(user).ConfigureAwait(false);
	}

	/// <summary>
	///     Email is the username (2026-10-24 explicit-writes spec §3.1): sets <c>UserName</c> to the same value, so
	///     the base call's one <see cref="UpdateUserAsync" /> writes the email, the username, both lookup hashes and
	///     the rotated security stamp together -- one flush, one <c>users</c> history version.
	/// </summary>
	/// <inheritdoc />
	public override async Task<IdentityResult> SetEmailAsync(NorseUser user, string? email)
	{
		ArgumentNullException.ThrowIfNull(user);
		await Store.SetUserNameAsync(user, email, CancellationToken).ConfigureAwait(false);
		return AsDuplicateEmail(await base.SetEmailAsync(user, email).ConfigureAwait(false), email);
	}

	/// <summary>
	///     Email is the username (spec §3.1): once the token verifies, sets <c>UserName</c> to the new address, so
	///     the base call's one <see cref="UpdateUserAsync" /> writes both values, both lookup hashes and the rotated
	///     security stamp together. The token is checked first so a refused change leaves the instance untouched.
	///     The base call checks it again, and a token expiring between the two checks fails there without reaching
	///     <see cref="UpdateUserAsync" />, so that failure abandons the username set here.
	/// </summary>
	/// <inheritdoc />
	public override async Task<IdentityResult> ChangeEmailAsync(NorseUser user, string newEmail, string token)
	{
		ArgumentNullException.ThrowIfNull(user);
		if (!await VerifyUserTokenAsync(user, Options.Tokens.ChangeEmailTokenProvider,
				GetChangeEmailTokenPurpose(newEmail), token).ConfigureAwait(false))
			return IdentityResult.Failed(ErrorDescriber.InvalidToken());

		return AsDuplicateEmail(await AbandoningOnFailureAsync(user, async () =>
		{
			await Store.SetUserNameAsync(user, newEmail, CancellationToken).ConfigureAwait(false);
			return await base.ChangeEmailAsync(user, newEmail, token).ConfigureAwait(false);
		}).ConfigureAwait(false), newEmail);
	}

	/// <summary>
	///     Refused (spec §3.1): the username is derived from the email, never set on its own. Change it with
	///     <see cref="SetEmailAsync" /> or <see cref="ChangeEmailAsync" />. Answers a failed
	///     <see cref="IdentityResult" /> carrying <see cref="UserNameIsDerivedErrorCode" />, and writes nothing.
	/// </summary>
	/// <inheritdoc />
	public override Task<IdentityResult> SetUserNameAsync(NorseUser user, string? userName) =>
		Task.FromResult(IdentityResult.Failed(new IdentityError
		{
			Code = UserNameIsDerivedErrorCode,
			Description = "The username is the email address; change it with SetEmailAsync or ChangeEmailAsync."
		}));

	/// <summary>
	///     Redemption writes before the update (2026-10-24 explicit-writes spec §4.5): the store consumes the code in
	///     its own committed statement, encrypting the remaining set, so the scope must wrap the store call too, not
	///     only the update that follows.
	/// </summary>
	/// <inheritdoc />
	public override async Task<IdentityResult> RedeemTwoFactorRecoveryCodeAsync(NorseUser user, string code)
	{
		ArgumentNullException.ThrowIfNull(user);
		using (SubjectCryptoScope.Begin(user.Id))
			return await base.RedeemTwoFactorRecoveryCodeAsync(user, code).ConfigureAwait(false);
	}

	/// <summary>
	///     The base loop, losslessly: generates <paramref name="number" /> distinct codes, stages them on the store, and
	///     answers the update's own result beside them, so an indeterminate commit reaches the caller instead of the
	///     <see langword="null" /> <see cref="GenerateNewTwoFactorRecoveryCodesAsync" /> answers for every failure.
	///     <see cref="UpdateUserAsync" /> opens the subject's crypto scope, and the store encrypts the staged set inside
	///     it at the flush.
	/// </summary>
	/// <inheritdoc />
	/// <exception cref="NotSupportedException">The store is not an <see cref="IUserTwoFactorRecoveryCodeStore{TUser}" />.</exception>
	public async Task<(IdentityResult Result, string[] Codes)> ReplaceRecoveryCodesAsync(NorseUser user, int number)
	{
		ThrowIfDisposed();
		var recoveryCodes = Store as IUserTwoFactorRecoveryCodeStore<NorseUser> ??
			throw new NotSupportedException("The store does not implement IUserTwoFactorRecoveryCodeStore<NorseUser>.");
		ArgumentNullException.ThrowIfNull(user);
		HashSet<string> codes = new(number, StringComparer.Ordinal);
		while (codes.Count < number)
			codes.Add(CreateTwoFactorRecoveryCode());

		await recoveryCodes.ReplaceCodesAsync(user, codes, CancellationToken).ConfigureAwait(false);
		var result = await UpdateUserAsync(user).ConfigureAwait(false);
		return (result, [.. codes]);
	}

	/// <summary>
	///     Delegates to <see cref="ReplaceRecoveryCodesAsync" />, answering the framework's contract: the codes on
	///     success, <see langword="null" /> otherwise. Kept for the framework's own callers; Norse code goes through
	///     <c>.Outcome.ReplaceRecoveryCodesAsync</c>, and the IL scan bans this name.
	/// </summary>
	/// <inheritdoc />
	public override async Task<IEnumerable<string>?> GenerateNewTwoFactorRecoveryCodesAsync(NorseUser user, int number)
	{
		var (result, codes) = await ReplaceRecoveryCodesAsync(user, number).ConfigureAwait(false);
		return result.Succeeded ?
			codes :
			null;
	}

	/// <summary>
	///     Idempotent provisioning (the setup page loads twice, prerender then interactive): a stored key answers
	///     <see cref="IdentityResult.Success" /> with no write; otherwise a new key is staged and flushed through
	///     <see cref="UpdateUserAsync" />, which opens the subject's crypto scope, and the update's own result answers.
	///     Over <see cref="NorseUserStore" /> the write is insert-if-absent and the key is re-read after it, so a
	///     concurrent first setup that stored first wins and both answer its key (Train 3 Task 4.4).
	///     Unlike <see cref="UserManager{TUser}.ResetAuthenticatorKeyAsync" />, the security stamp is not rotated: no
	///     credential exists until the key is verified, so no session needs to die.
	/// </summary>
	/// <inheritdoc />
	/// <exception cref="NotSupportedException">The store is not an <see cref="IUserAuthenticatorKeyStore{TUser}" />.</exception>
	public async Task<(IdentityResult Result, string Key)> ProvisionAuthenticatorKeyAsync(NorseUser user)
	{
		ThrowIfDisposed();
		var authenticatorKeys = Store as IUserAuthenticatorKeyStore<NorseUser> ??
			throw new NotSupportedException("The store does not implement IUserAuthenticatorKeyStore<NorseUser>.");
		ArgumentNullException.ThrowIfNull(user);
		if (await authenticatorKeys.GetAuthenticatorKeyAsync(user, CancellationToken).ConfigureAwait(false) is
			{ Length: > 0 } existing)
			return (IdentityResult.Success, existing);

		// Conditional on the explicit-writes store: a concurrent first setup that stored its key first wins, and this
		// flush writes nothing. Any other store keeps the plain write.
		var key = GenerateNewAuthenticatorKey();
		if (Store is NorseUserStore)
			NorseUserStore.StageAuthenticatorKeyIfAbsent(user, key);
		else
			await authenticatorKeys.SetAuthenticatorKeyAsync(user, key, CancellationToken).ConfigureAwait(false);
		var result = await UpdateUserAsync(user).ConfigureAwait(false);
		if (!result.Succeeded)
			return (result, key);

		// The key actually stored, which is this one or the racer's: the one every concurrent setup answers. A write
		// that reported success yet left no key stored fails closed: a key nobody stored could never verify.
		var stored = await authenticatorKeys.GetAuthenticatorKeyAsync(user, CancellationToken).ConfigureAwait(false);
		return string.IsNullOrEmpty(stored) ?
			(IdentityResult.Failed(new IdentityError
			{
				Code = NorseIdentityErrorCodes.AuthenticatorKeyNotStored,
				Description = "The authenticator key was not stored."
			}), string.Empty) :
			(result, stored);
	}

	/// <summary>
	///     V5: the stock loop stages each membership, then returns <c>UserAlreadyInRole</c> for a role already held
	///     without reaching <see cref="UpdateUserAsync" />, so a failure here abandons the memberships staged before it.
	/// </summary>
	/// <inheritdoc />
	public override Task<IdentityResult> AddToRolesAsync(NorseUser user, IEnumerable<string> roles) =>
		AbandoningOnFailureAsync(user, () => base.AddToRolesAsync(user, roles));

	/// <summary>
	///     V5: the stock loop stages each removal, then returns <c>UserNotInRole</c> for a role not held without
	///     reaching <see cref="UpdateUserAsync" />, so a failure here abandons the removals staged before it.
	/// </summary>
	/// <inheritdoc />
	public override Task<IdentityResult> RemoveFromRolesAsync(NorseUser user, IEnumerable<string> roles) =>
		AbandoningOnFailureAsync(user, () => base.RemoveFromRolesAsync(user, roles));

	/// <summary>
	///     Validates, then hands the instance to the store's flush, inside the subject's crypto scope. The abandon
	///     hook (spec §4.8): any failure -- validation refusing the instance before <c>Store.UpdateAsync</c> runs, or
	///     the store failing it -- drops what was staged on the instance and restores it to its baseline, so the next
	///     operation never carries the leftovers.
	/// </summary>
	/// <inheritdoc />
	/// <exception cref="InvalidOperationException">
	///     <paramref name="user" /> has no id yet (<see cref="Guid.Empty" />). Establishing the ambient scope
	///     on an empty id would mint a DEK for nobody -- the exact silent fallback
	///     <see cref="SubjectCryptoScope" /> exists to forbid -- so this fails loudly before the store is
	///     ever called instead of quietly encrypting under an all-zeros subject.
	/// </exception>
	protected override async Task<IdentityResult> UpdateUserAsync(NorseUser user)
	{
		ArgumentNullException.ThrowIfNull(user);
		if (user.Id == Guid.Empty)
			throw new InvalidOperationException(
				"NorseUserManager.UpdateUserAsync was called with an empty user id -- the subject must exist (see CreateAsync) before the store can establish an ambient crypto scope and encrypt.");
		using (SubjectCryptoScope.Begin(user.Id))
			return await AbandoningOnFailureAsync(user, () => base.UpdateUserAsync(user)).ConfigureAwait(false);
	}

	/// <summary>
	///     Runs <paramref name="operation" />, abandoning the instance's staged state (spec §4.8) unless it succeeds,
	///     whether it fails by result or by exception.
	/// </summary>
	static async Task<IdentityResult> AbandoningOnFailureAsync(NorseUser user, Func<Task<IdentityResult>> operation)
	{
		var succeeded = false;
		try
		{
			var result = await operation().ConfigureAwait(false);
			succeeded = result.Succeeded;
			return result;
		}
		finally
		{
			if (!succeeded)
				NorseUserStore.Abandon(user);
		}
	}

	/// <summary>
	///     Email is the username (spec §3.1), so on an email change a taken username is a taken email: the store's
	///     <c>DuplicateUserName</c> (a race past the validator, decided by the unique index) and the validator's pair
	///     of duplicates both answer as one <c>DuplicateEmail</c>.
	/// </summary>
	IdentityResult AsDuplicateEmail(IdentityResult result, string? email) =>
		result.Errors.Any(static error => error.Code is nameof(IdentityErrorDescriber.DuplicateUserName)) ?
			IdentityResult.Failed([
				ErrorDescriber.DuplicateEmail(email ?? string.Empty),
				.. result.Errors.Where(static error =>
					error.Code is not (nameof(IdentityErrorDescriber.DuplicateUserName) or nameof(IdentityErrorDescriber.DuplicateEmail)))
			]) :
			result;
}
