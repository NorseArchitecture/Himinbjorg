using System.Data.Common;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.ExceptionServices;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;
using Norse.Identity.Web.Server.Store;

namespace Norse.Identity.Web.Server;

/// <summary>
///     The Norse platform's explicit-write user store (2026-10-24 explicit-writes spec §4), registered by
///     <c>AddNorseIdentity</c>. It implements Identity's store interfaces directly, with no <c>UserStore</c> base and
///     no inherited code that assumes tracking: every read is untracked and whole (both fragments), and every instance
///     it hands out carries an as-read <see cref="UserBaseline" />.
/// </summary>
/// <remarks>
///     <para>
///         <see cref="IQueryableUserStore{TUser}" /> is deliberately not implemented: an <c>IQueryable</c> door
///         invites list-shaped decrypted reads (PII spec §4.1, the subject-singular read law). For the same reason
///         <see cref="GetUsersForClaimAsync" /> and <see cref="GetUsersInRoleAsync" /> are refused (§4.9), and
///         <see cref="DeleteAsync" /> is refused because erasure has one door (§4.7).
///     </para>
///     <para>
///         Lookup protection stays in <see cref="UserManager{TUser}" />: the normalized values this store receives
///         are already blind-indexed. Scalar setters only assign, and the intents the diff can't express are
///         staged; <see cref="UpdateAsync" /> diffs the instance against its baseline and flushes.
///     </para>
/// </remarks>
/// <param name="context">The Identity database context.</param>
/// <param name="describer">The source of the <see cref="IdentityError" />s a refused flush answers.</param>
public sealed class NorseUserStore(NorseIdentityDbContext context, IdentityErrorDescriber describer) :
	IUserPasswordStore<NorseUser>,
	IUserSecurityStampStore<NorseUser>,
	IUserEmailStore<NorseUser>,
	IUserPhoneNumberStore<NorseUser>,
	IUserLockoutStore<NorseUser>,
	IUserTwoFactorStore<NorseUser>,
	IUserAuthenticatorKeyStore<NorseUser>,
	IUserTwoFactorRecoveryCodeStore<NorseUser>,
	IUserAuthenticationTokenStore<NorseUser>,
	IUserLoginStore<NorseUser>,
	IUserClaimStore<NorseUser>,
	IUserRoleStore<NorseUser>,
	IUserPasskeyStore<NorseUser>,
	IProtectedUserStore<NorseUser>
{
	/// <summary>
	///     The <see cref="IdentityError.Code" /> a passkey enrollment answers when its credential id is already
	///     registered to another user or under another public key (2026-10-24 explicit-writes spec §4.6).
	/// </summary>
	public const string PasskeyAlreadyRegisteredErrorCode = NorseIdentityErrorCodes.PasskeyAlreadyRegistered;

	/// <summary>
	///     The <see cref="IdentityError.Code" /> a flush answers when its commit may or may not have taken effect and no
	///     stamp marker resolves it (2026-10-24 explicit-writes spec §4.10). The instance is poisoned: re-read, then
	///     repeat the manager operation.
	/// </summary>
	public const string IndeterminateOutcomeErrorCode = NorseIdentityErrorCodes.IndeterminateOutcome;

	/// <summary>
	///     The <see cref="IdentityError.Code" /> a flush answers when a staged login removal would leave the user with no
	///     password and no external login (2026-10-26 account-lifecycle spec §5.9). Nothing is written.
	/// </summary>
	public const string LastSignInMethodErrorCode = NorseIdentityErrorCodes.LastSignInMethod;

	/// <summary>Stock Identity's login provider for the tokens it keeps itself (<c>UserStoreBase</c>).</summary>
	const string InternalLoginProvider = "[AspNetUserStore]";

	/// <summary>Stock Identity's token name for the recovery-code set, stored <c>;</c>-joined.</summary>
	const string RecoveryCodeTokenName = "RecoveryCodes";

	/// <summary>Stock Identity's token name for the authenticator key.</summary>
	const string AuthenticatorKeyTokenName = "AuthenticatorKey";

	/// <summary>How many compare-and-swap attempts one redemption makes before it gives up (spec §4.5).</summary>
	const int RedemptionAttempts = 5;
	const string MultiSubjectReadRefused =
		"Refused by the subject-singular read law (PII spec §4.1): a list of users would materialize many subjects' decrypted personal data. Answer with ids and masked projections through the disclosure contract instead.";

	/// <summary>
	///     The as-read baseline of every instance this store has handed out, in any scope. Static and weak, so a
	///     baseline lives exactly as long as its instance and follows it across DI scopes.
	/// </summary>
	static readonly ConditionalWeakTable<NorseUser, UserBaseline> _baselines = new();

	/// <summary>
	///     The intents staged against each instance since its last flush (spec §4.3), held alongside its baseline and
	///     weak in the same way. Every flush drains them, whatever its outcome.
	/// </summary>
	static readonly ConditionalWeakTable<NorseUser, List<StagedIntent>> _staged = new();

	/// <summary>The as-read baseline this store attached to <paramref name="user" />, if any.</summary>
	/// <param name="user">An instance, wherever it came from.</param>
	/// <param name="baseline">The baseline, when the store read or created the instance.</param>
	internal static bool TryGetBaseline(NorseUser user, [NotNullWhen(true)] out UserBaseline? baseline) =>
		_baselines.TryGetValue(user, out baseline);

	/// <summary>
	///     The manager's abandon hook (2026-10-24 explicit-writes spec §4.8): an operation failed without its flush
	///     deciding the outcome -- validation refused it before <see cref="UpdateAsync" />, or it returned early after
	///     staging -- so the instance's staged intents are dropped and its mapped properties and stamp put back to the
	///     baseline, which stays as it is. Idempotent, and safe after a flush that already restored the instance. A
	///     poisoned instance (§4.10) has no baseline, so only its intents are dropped and it is never restored; neither
	///     is an instance this store never read or created.
	/// </summary>
	/// <param name="user">The instance whose operation failed.</param>
	internal static void Abandon(NorseUser user)
	{
		_staged.Remove(user);
		if (_baselines.TryGetValue(user, out var baseline))
			baseline.Restore(user);
	}

	/// <inheritdoc />
	public Task<string> GetUserIdAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		Task.FromResult(user.Id.ToString());

	/// <inheritdoc />
	public Task<string?> GetUserNameAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		Task.FromResult(user.UserName);

	/// <inheritdoc />
	public Task SetUserNameAsync(NorseUser user, string? userName, CancellationToken cancellationToken = default)
	{
		user.UserName = userName;
		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task<string?> GetNormalizedUserNameAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		Task.FromResult(user.NormalizedUserName);

	/// <inheritdoc />
	public Task SetNormalizedUserNameAsync(NorseUser user, string? normalizedName,
		CancellationToken cancellationToken = default)
	{
		user.NormalizedUserName = normalizedName;
		return Task.CompletedTask;
	}

	/// <summary>
	///     Inserts both fragments, then any child-row intents staged against the new instance, in one explicit
	///     transaction under a strategy that never retries; then attaches the inserted values as the instance's
	///     baseline. A refused child intent rolls everything back and answers its failure.
	/// </summary>
	/// <inheritdoc />
	public async Task<IdentityResult> CreateAsync(NorseUser user, CancellationToken cancellationToken = default)
	{
		IReadOnlyList<StagedIntent> intents = _staged.TryGetValue(user, out var staged) ?
			staged :
			[];
		_staged.Remove(user);
		var result = await new ZeroRetryExecutionStrategy(context)
			.ExecuteAsync((user, intents), InsertAsync, cancellationToken)
			.ConfigureAwait(false);
		if (result.Succeeded)
			_baselines.AddOrUpdate(user, UserBaseline.Capture(user).WithPasskeyIntents(intents));
		return result;
	}

	/// <summary>
	///     Flushes (spec §4.3): diffs the instance against its baseline and writes only what changed, in one
	///     transaction under a strategy that never retries -- the <c>users</c> statement only if a <c>users</c>
	///     column changed, then the credentials statement. After the commit the instance carries the new stamp and
	///     its baseline becomes what was committed. A definite failure (§4.8) leaves the instance exactly as read and
	///     the baseline untouched: a moved stamp or a failed credential swap answers <c>ConcurrencyFailure</c>, a
	///     username taken in a race answers <c>DuplicateUserName</c>, and anything else is rethrown. A commit that may
	///     have landed is resolved by its stamp marker where the flush wrote <c>users</c>, and otherwise answers
	///     <see cref="IndeterminateOutcomeErrorCode" /> and poisons the instance (§4.10).
	/// </summary>
	/// <inheritdoc />
	/// <exception cref="InvalidOperationException">
	///     <paramref name="user" /> carries no as-read baseline. Refused (spec §4.2): there is no silent blanket write.
	/// </exception>
	public async Task<IdentityResult> UpdateAsync(NorseUser user, CancellationToken cancellationToken = default)
	{
		if (!_baselines.TryGetValue(user, out var baseline))
			throw new InvalidOperationException(
				$"User {user.Id} has no as-read baseline: this store neither read nor created this instance (it was constructed by hand, deserialized or copied), so it cannot tell what changed. Re-read the user through the UserManager, then apply the change to that instance.");

		IReadOnlyList<StagedIntent> intents = _staged.TryGetValue(user, out var staged) ?
			staged :
			[];
		_staged.Remove(user);
		FlushExecutor flush = new(context, describer);
		IdentityResult result;
		try
		{
			result = await new ZeroRetryExecutionStrategy(context)
				.ExecuteAsync((user, baseline, intents), flush.FlushAsync, cancellationToken)
				.ConfigureAwait(false);
		}
		catch (IndeterminateWriteException indeterminate)
		{
			// The commit may have landed, so the instance is not restored (§4.10).
			return await ResolveAsync((user, baseline, intents), flush.Marker, indeterminate).ConfigureAwait(false);
		}
		catch (Exception)
		{
			// Definite: nothing committed.
			baseline.Restore(user);
			throw;
		}

		if (result.Succeeded)
			_baselines.AddOrUpdate(user, baseline.Refreshed(user).WithPasskeyIntents(intents));
		else
			baseline.Restore(user);
		return result;
	}

	/// <summary>Refused (spec §4.7): erasure has one door.</summary>
	/// <inheritdoc />
	/// <exception cref="NotSupportedException">Always.</exception>
	public Task<IdentityResult> DeleteAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		throw new NotSupportedException(
			$"Users are never deleted through the store: erase the subject with {nameof(ErasureService)}.{nameof(ErasureService.ShredAsync)}, which destroys the subject key first and then removes the row and its OpenIddict state.");

	/// <inheritdoc />
	public Task<NorseUser?> FindByIdAsync(string userId, CancellationToken cancellationToken = default)
	{
		var id = Guid.Parse(userId);
		return ReadAsync(context.Users.Where(u => u.Id == id), cancellationToken);
	}

	/// <inheritdoc />
	public Task<NorseUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default) =>
		ReadAsync(context.Users.Where(u => u.NormalizedUserName == normalizedUserName), cancellationToken);

	/// <summary>Nothing to release: the context belongs to the DI scope.</summary>
	public void Dispose()
	{
	}

	/// <inheritdoc />
	public Task SetPasswordHashAsync(NorseUser user, string? passwordHash, CancellationToken cancellationToken = default)
	{
		user.PasswordHash = passwordHash;
		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task<string?> GetPasswordHashAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		Task.FromResult(user.PasswordHash);

	/// <inheritdoc />
	public Task<bool> HasPasswordAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		Task.FromResult(user.PasswordHash is not null);

	/// <inheritdoc />
	public Task SetSecurityStampAsync(NorseUser user, string stamp, CancellationToken cancellationToken = default)
	{
		user.SecurityStamp = stamp;
		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task<string?> GetSecurityStampAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		Task.FromResult(user.SecurityStamp);

	/// <inheritdoc />
	public Task SetEmailAsync(NorseUser user, string? email, CancellationToken cancellationToken = default)
	{
		user.Email = email;
		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task<string?> GetEmailAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		Task.FromResult(user.Email);

	/// <inheritdoc />
	public Task<bool> GetEmailConfirmedAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		Task.FromResult(user.EmailConfirmed);

	/// <inheritdoc />
	public Task SetEmailConfirmedAsync(NorseUser user, bool confirmed, CancellationToken cancellationToken = default)
	{
		user.EmailConfirmed = confirmed;
		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task<NorseUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default) =>
		ReadAsync(context.Users.Where(u => u.NormalizedEmail == normalizedEmail), cancellationToken);

	/// <inheritdoc />
	public Task<string?> GetNormalizedEmailAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		Task.FromResult(user.NormalizedEmail);

	/// <inheritdoc />
	public Task SetNormalizedEmailAsync(NorseUser user, string? normalizedEmail,
		CancellationToken cancellationToken = default)
	{
		user.NormalizedEmail = normalizedEmail;
		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task SetPhoneNumberAsync(NorseUser user, string? phoneNumber, CancellationToken cancellationToken = default)
	{
		user.PhoneNumber = phoneNumber;
		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task<string?> GetPhoneNumberAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		Task.FromResult(user.PhoneNumber);

	/// <inheritdoc />
	public Task<bool> GetPhoneNumberConfirmedAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		Task.FromResult(user.PhoneNumberConfirmed);

	/// <inheritdoc />
	public Task SetPhoneNumberConfirmedAsync(NorseUser user, bool confirmed,
		CancellationToken cancellationToken = default)
	{
		user.PhoneNumberConfirmed = confirmed;
		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task<DateTimeOffset?> GetLockoutEndDateAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		Task.FromResult(user.LockoutEnd);

	/// <inheritdoc />
	public Task SetLockoutEndDateAsync(NorseUser user, DateTimeOffset? lockoutEnd,
		CancellationToken cancellationToken = default)
	{
		user.LockoutEnd = lockoutEnd;
		return Task.CompletedTask;
	}

	/// <summary>
	///     The immediate increment (spec §4.5), never staged: <c>access_failed_count + 1</c> as one statement in its
	///     own explicit transaction, committed before the manager acts on the count, under a strategy that never
	///     retries. Concurrent failures each get a distinct count. The instance and its baseline take the returned
	///     count, so the update that follows has nothing of it to write. An increment whose commit may have landed is
	///     never repeated (§4.10): the instance is poisoned and the failure thrown, so sign-in fails closed.
	/// </summary>
	/// <inheritdoc />
	/// <exception cref="IndeterminateWriteException">The increment's commit failed and may have taken effect.</exception>
	public async Task<int> IncrementAccessFailedCountAsync(NorseUser user, CancellationToken cancellationToken = default)
	{
		int count;
		try
		{
			count = await new ZeroRetryExecutionStrategy(context)
				.ExecuteAsync(user.Id, IncrementAsync, cancellationToken)
				.ConfigureAwait(false);
		}
		catch (IndeterminateWriteException)
		{
			Poison(user);
			throw;
		}

		user.AccessFailedCount = count;
		if (_baselines.TryGetValue(user, out var baseline))
			_baselines.AddOrUpdate(user, baseline with { AccessFailedCount = count });
		return count;
	}

	/// <summary>Stages the unconditional reset (spec §4.4): the flush writes <c>0</c> whatever the stored count.</summary>
	/// <inheritdoc />
	public Task ResetAccessFailedCountAsync(NorseUser user, CancellationToken cancellationToken = default)
	{
		user.AccessFailedCount = 0;
		Stage(user, StagedIntent.ResetAccessFailedCount.Instance);
		return Task.CompletedTask;
	}

	/// <summary>
	///     Reads the database, not the instance (spec §4.5): the manager decides on this count, and a concurrent
	///     failure may have raised it since the instance was read. The instance is left as it is.
	/// </summary>
	/// <inheritdoc />
	public Task<int> GetAccessFailedCountAsync(NorseUser user, CancellationToken cancellationToken = default)
	{
		var id = user.Id;
		return context.Users
			.AsNoTracking()
			.Where(u => u.Id == id)
			.Select(static u => u.AccessFailedCount)
			.SingleAsync(cancellationToken);
	}

	/// <inheritdoc />
	public Task<bool> GetLockoutEnabledAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		Task.FromResult(user.LockoutEnabled);

	/// <inheritdoc />
	public Task SetLockoutEnabledAsync(NorseUser user, bool enabled, CancellationToken cancellationToken = default)
	{
		user.LockoutEnabled = enabled;
		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task SetTwoFactorEnabledAsync(NorseUser user, bool enabled, CancellationToken cancellationToken = default)
	{
		user.TwoFactorEnabled = enabled;
		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task<bool> GetTwoFactorEnabledAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		Task.FromResult(user.TwoFactorEnabled);

	/// <summary>Stages the authenticator key's upsert, as stock Identity keeps it: a token of its own.</summary>
	/// <inheritdoc />
	public Task SetAuthenticatorKeyAsync(NorseUser user, string key, CancellationToken cancellationToken = default) =>
		SetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, key, cancellationToken);

	/// <summary>
	///     Stages the authenticator key's insert-if-absent (<see cref="StagedIntent.InsertTokenIfAbsent" />): the first
	///     provisioning's write, which never replaces a key a concurrent setup stored first. A reset still goes through
	///     <see cref="SetAuthenticatorKeyAsync" />, whose upsert does replace.
	/// </summary>
	/// <param name="user">The user.</param>
	/// <param name="key">The newly generated key.</param>
	internal static void StageAuthenticatorKeyIfAbsent(NorseUser user, string key) =>
		Stage(user, new StagedIntent.InsertTokenIfAbsent(InternalLoginProvider, AuthenticatorKeyTokenName, key));

	/// <summary>Reads the database, not the instance (spec §4.5).</summary>
	/// <inheritdoc />
	public Task<string?> GetAuthenticatorKeyAsync(NorseUser user, CancellationToken cancellationToken = default) =>
		GetTokenAsync(user, InternalLoginProvider, AuthenticatorKeyTokenName, cancellationToken);

	/// <summary>
	///     Stages the new code set's upsert (spec §4.5): a replacement racing a redemption ends with the new set, which
	///     is the intended result.
	/// </summary>
	/// <inheritdoc />
	public Task ReplaceCodesAsync(NorseUser user, IEnumerable<string> recoveryCodes,
		CancellationToken cancellationToken = default) =>
		SetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, string.Join(';', recoveryCodes), cancellationToken);

	/// <summary>
	///     Atomic consumption (spec §4.5), distinct from replacing the set: reads the stored set, and when it holds
	///     <paramref name="code" />, swaps it for the set without that code, guarded by the value just read -- one
	///     statement in its own explicit transaction per attempt, under a strategy that never retries. A swap that
	///     matches nothing means another redemption or replacement committed in between: re-read and try again, at
	///     most five times. Committed immediately, so a consumed code stays consumed whatever follows. Needs the
	///     caller's crypto scope, since the new set is encrypted. A swap whose commit may have landed is never repeated
	///     (§4.10): the instance is poisoned and the failure thrown, so the code may already be spent.
	/// </summary>
	/// <inheritdoc />
	/// <exception cref="DbUpdateConcurrencyException">Every attempt's swap was beaten by a concurrent write.</exception>
	/// <exception cref="IndeterminateWriteException">A swap's commit failed and may have taken effect.</exception>
	public async Task<bool> RedeemCodeAsync(NorseUser user, string code, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(code);
		(Guid, string, string) key = (user.Id, InternalLoginProvider, RecoveryCodeTokenName);
		var value = context.UserTokens.EntityType.GetProperty(nameof(NorseUserToken.Value));
		var converter = value.GetTypeMapping().Converter;
		for (var attempt = 0; attempt < RedemptionAttempts; attempt++)
		{
			var (exists, stored) = await ProviderStatements
				.ReadStoredTokenAsync(context, key, cancellationToken)
				.ConfigureAwait(false);
			if (!exists || stored is null)
				return false;

			var codes = (converter is null ?
				stored :
				(string?)converter.ConvertFromProvider(stored) ?? string.Empty).Split(';');
			if (!codes.Contains(code, StringComparer.Ordinal))
				return false;

			var remaining = string.Join(';', codes.Where(c => !string.Equals(c, code, StringComparison.Ordinal)));
			int swapped;
			try
			{
				swapped = await new ZeroRetryExecutionStrategy(context)
					.ExecuteAsync((key, remaining, stored), SwapAsync, cancellationToken)
					.ConfigureAwait(false);
			}
			catch (IndeterminateWriteException)
			{
				Poison(user);
				throw;
			}

			if (swapped is 1)
				return true;
		}

		throw new DbUpdateConcurrencyException(
			$"Redeeming a recovery code for user {user.Id} lost the race {RedemptionAttempts} times in a row: every swap was beaten by a concurrent change to the set. Nothing was redeemed.");
	}

	/// <summary>Reads the database, not the instance (spec §4.5), counting as stock Identity counts.</summary>
	/// <inheritdoc />
	public async Task<int> CountCodesAsync(NorseUser user, CancellationToken cancellationToken = default)
	{
		var codes = await GetTokenAsync(user, InternalLoginProvider, RecoveryCodeTokenName, cancellationToken).ConfigureAwait(false) ??
			string.Empty;
		return codes.Length is 0 ?
			0 :
			codes.Count(';') + 1;
	}

	/// <summary>
	///     Stages the token upsert (spec §4.6): the flush writes it with the provider-native upsert, so concurrent
	///     creators of one key both succeed and the last committed value wins. The value is encrypted when the flush
	///     binds it, under the manager's crypto scope.
	/// </summary>
	/// <inheritdoc />
	public Task SetTokenAsync(NorseUser user, string loginProvider, string name, string? value,
		CancellationToken cancellationToken = default)
	{
		Stage(user, new StagedIntent.UpsertToken(loginProvider, name, value));
		return Task.CompletedTask;
	}

	/// <summary>Stages the token's delete by key.</summary>
	/// <inheritdoc />
	public Task RemoveTokenAsync(NorseUser user, string loginProvider, string name,
		CancellationToken cancellationToken = default)
	{
		Stage(user, new StagedIntent.RemoveToken(loginProvider, name));
		return Task.CompletedTask;
	}

	/// <summary>Reads the database, not the instance (spec §4.5), decrypting through the model's converter.</summary>
	/// <inheritdoc />
	public Task<string?> GetTokenAsync(NorseUser user, string loginProvider, string name,
		CancellationToken cancellationToken = default)
	{
		var id = user.Id;
		return context.UserTokens
			.AsNoTracking()
			.Where(t => t.UserId == id && t.LoginProvider == loginProvider && t.Name == name)
			.Select(static t => t.Value)
			.SingleOrDefaultAsync(cancellationToken);
	}

	/// <summary>
	///     Stages the login's insert (spec §4.6). A conflict with the same user's row is a replay; one with another
	///     user's rolls the flush back and answers <c>LoginAlreadyAssociated</c>.
	/// </summary>
	/// <inheritdoc />
	public Task AddLoginAsync(NorseUser user, UserLoginInfo login, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(login);
		Stage(user, new StagedIntent.AddLogin(login.LoginProvider, login.ProviderKey, login.ProviderDisplayName));
		return Task.CompletedTask;
	}

	/// <summary>Stages the login's delete by key.</summary>
	/// <inheritdoc />
	public Task RemoveLoginAsync(NorseUser user, string loginProvider, string providerKey,
		CancellationToken cancellationToken = default)
	{
		Stage(user, new StagedIntent.RemoveLogin(loginProvider, providerKey));
		return Task.CompletedTask;
	}

	/// <summary>Reads the database, not the instance.</summary>
	/// <inheritdoc />
	public async Task<IList<UserLoginInfo>> GetLoginsAsync(NorseUser user, CancellationToken cancellationToken = default)
	{
		var id = user.Id;
		var logins = await context.UserLogins
			.AsNoTracking()
			.Where(l => l.UserId == id)
			.Select(static l => new { l.LoginProvider, l.ProviderKey, l.ProviderDisplayName })
			.ToListAsync(cancellationToken)
			.ConfigureAwait(false);
		return [.. logins.Select(static l => new UserLoginInfo(l.LoginProvider, l.ProviderKey, l.ProviderDisplayName))];
	}

	/// <inheritdoc />
	public Task<NorseUser?> FindByLoginAsync(string loginProvider, string providerKey,
		CancellationToken cancellationToken = default) =>
		ReadAsync(context.Users.Where(u => u.Logins.Any(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey)),
			cancellationToken);

	/// <summary>Reads the database, not the instance.</summary>
	/// <inheritdoc />
	public async Task<IList<Claim>> GetClaimsAsync(NorseUser user, CancellationToken cancellationToken = default)
	{
		var id = user.Id;
		var claims = await context.UserClaims
			.AsNoTracking()
			.Where(c => c.UserId == id)
			.Select(static c => new { c.ClaimType, c.ClaimValue })
			.ToListAsync(cancellationToken)
			.ConfigureAwait(false);
		return [.. claims.Select(static c => new Claim(c.ClaimType ?? string.Empty, c.ClaimValue ?? string.Empty))];
	}

	/// <summary>
	///     Stages an insert-if-absent per claim (spec §4.6): claims are a set, so an identical claim already held is a
	///     no-op, never a second row.
	/// </summary>
	/// <inheritdoc />
	public Task AddClaimsAsync(NorseUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(claims);
		foreach (var claim in claims)
			Stage(user, new StagedIntent.AddClaim(claim.Type, claim.Value));
		return Task.CompletedTask;
	}

	/// <summary>
	///     Stages the replacement (spec §4.6): the flush rewrites the claims matching the old type and value hash. A
	///     replay -- nothing matched, the new claim already present -- is success; nothing matched otherwise answers
	///     <c>ConcurrencyFailure</c>.
	/// </summary>
	/// <inheritdoc />
	public Task ReplaceClaimAsync(NorseUser user, Claim claim, Claim newClaim,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(claim);
		ArgumentNullException.ThrowIfNull(newClaim);
		// Replacing a claim with itself is no change: stage nothing, so nothing is rewritten and no history is minted.
		if (string.Equals(claim.Type, newClaim.Type, StringComparison.Ordinal) &&
			string.Equals(claim.Value, newClaim.Value, StringComparison.Ordinal))
			return Task.CompletedTask;

		Stage(user, new StagedIntent.ReplaceClaim(claim.Type, claim.Value, newClaim.Type, newClaim.Value));
		return Task.CompletedTask;
	}

	/// <summary>Stages a delete per claim, by type and value hash.</summary>
	/// <inheritdoc />
	public Task RemoveClaimsAsync(NorseUser user, IEnumerable<Claim> claims,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(claims);
		foreach (var claim in claims)
			Stage(user, new StagedIntent.RemoveClaim(claim.Type, claim.Value));
		return Task.CompletedTask;
	}

	/// <summary>Refused (spec §4.9).</summary>
	/// <inheritdoc />
	/// <exception cref="NotSupportedException">Always.</exception>
	public Task<IList<NorseUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default) =>
		throw new NotSupportedException(MultiSubjectReadRefused);

	/// <summary>
	///     Resolves the role now, as stock Identity does, and stages the membership's insert-if-absent (spec §4.6).
	/// </summary>
	/// <inheritdoc />
	/// <exception cref="InvalidOperationException">No role carries <paramref name="roleName" />.</exception>
	public async Task AddToRoleAsync(NorseUser user, string roleName,
		CancellationToken cancellationToken = default)
	{
		var roleId = await FindRoleIdAsync(roleName, cancellationToken).ConfigureAwait(false) ??
			throw new InvalidOperationException($"Role {roleName} does not exist.");
		Stage(user, new StagedIntent.AddRole(roleId));
	}

	/// <summary>Resolves the role now and stages the membership's delete by key; an unknown role is nothing to remove.</summary>
	/// <inheritdoc />
	public async Task RemoveFromRoleAsync(NorseUser user, string roleName,
		CancellationToken cancellationToken = default)
	{
		if (await FindRoleIdAsync(roleName, cancellationToken).ConfigureAwait(false) is { } roleId)
			Stage(user, new StagedIntent.RemoveRole(roleId));
	}

	/// <summary>Reads the database, not the instance.</summary>
	/// <inheritdoc />
	public async Task<IList<string>> GetRolesAsync(NorseUser user, CancellationToken cancellationToken = default)
	{
		var id = user.Id;
		return await context.UserRoles
			.AsNoTracking()
			.Where(ur => ur.UserId == id)
			.Select(static ur => ur.Role.Name ?? string.Empty)
			.ToListAsync(cancellationToken)
			.ConfigureAwait(false);
	}

	/// <summary>Reads the database, not the instance.</summary>
	/// <inheritdoc />
	public Task<bool> IsInRoleAsync(NorseUser user, string roleName,
		CancellationToken cancellationToken = default)
	{
		var id = user.Id;
		return context.UserRoles
			.AsNoTracking()
			.AnyAsync(ur => ur.UserId == id && ur.Role.NormalizedName == roleName, cancellationToken);
	}

	/// <summary>Refused (spec §4.9).</summary>
	/// <inheritdoc />
	/// <exception cref="NotSupportedException">Always.</exception>
	public Task<IList<NorseUser>> GetUsersInRoleAsync(string roleName,
		CancellationToken cancellationToken = default) =>
		throw new NotSupportedException(MultiSubjectReadRefused);

	/// <summary>
	///     Separates the method's two purposes by the instance's as-read passkey state (spec §4.6). A credential the
	///     store returned for this instance -- as <c>PasskeyHandler</c> reads it before validating an assertion, and as
	///     a rename reads it -- stages an assertion update guarded by the as-read sign count, so a delayed assertion or
	///     a removed credential fails the flush and is never re-inserted. Any other credential stages an enrollment
	///     insert. As stock Identity does, an update writes only the name, sign count and flags; the public key and
	///     the attestation never change.
	/// </summary>
	/// <inheritdoc />
	public Task AddOrUpdatePasskeyAsync(NorseUser user, UserPasskeyInfo passkey,
		CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(passkey);
		var asRead = _baselines.TryGetValue(user, out var baseline) ?
			baseline.PasskeySignCount(passkey.CredentialId) :
			null;
		Stage(user, asRead is { } signCount ?
			new StagedIntent.UpdatePasskey([.. passkey.CredentialId], signCount, passkey.Name, passkey.SignCount, passkey.IsUserVerified,
				passkey.IsBackedUp) :
			new StagedIntent.EnrollPasskey([.. passkey.CredentialId], new()
			{
				PublicKey = passkey.PublicKey,
				Name = passkey.Name,
				CreatedAt = passkey.CreatedAt,
				SignCount = passkey.SignCount,
				Transports = passkey.Transports,
				IsUserVerified = passkey.IsUserVerified,
				IsBackupEligible = passkey.IsBackupEligible,
				IsBackedUp = passkey.IsBackedUp,
				AttestationObject = passkey.AttestationObject,
				ClientDataJson = passkey.ClientDataJson,
				Aaguid = passkey.Aaguid
			}));
		return Task.CompletedTask;
	}

	/// <summary>Reads the user's passkeys and records each one's sign count in the instance's baseline.</summary>
	/// <inheritdoc />
	public async Task<IList<UserPasskeyInfo>> GetPasskeysAsync(NorseUser user,
		CancellationToken cancellationToken = default)
	{
		var passkeys = await context.UserPasskeys
			.AsNoTracking()
			.Where(p => p.UserId == user.Id)
			.ToListAsync(cancellationToken)
			.ConfigureAwait(false);
		RecordPasskeys(user, passkeys);
		return [.. passkeys.Select(ToInfo)];
	}

	/// <inheritdoc />
	public Task<NorseUser?> FindByPasskeyIdAsync(byte[] credentialId, CancellationToken cancellationToken = default) =>
		ReadAsync(context.Users.Where(u => u.Passkeys.Any(p => p.CredentialId.SequenceEqual(credentialId))),
			cancellationToken);

	/// <summary>Reads one of the user's passkeys and records its sign count in the instance's baseline.</summary>
	/// <inheritdoc />
	public async Task<UserPasskeyInfo?> FindPasskeyAsync(NorseUser user, byte[] credentialId,
		CancellationToken cancellationToken = default)
	{
		var passkey = await context.UserPasskeys
			.AsNoTracking()
			.SingleOrDefaultAsync(p => p.UserId == user.Id && p.CredentialId.SequenceEqual(credentialId), cancellationToken)
			.ConfigureAwait(false);
		if (passkey is null)
			return null;

		RecordPasskeys(user, [passkey]);
		return ToInfo(passkey);
	}

	/// <summary>Stages the passkey's delete by credential id.</summary>
	/// <inheritdoc />
	public Task RemovePasskeyAsync(NorseUser user, byte[] credentialId, CancellationToken cancellationToken = default)
	{
		ArgumentNullException.ThrowIfNull(credentialId);
		Stage(user, new StagedIntent.RemovePasskey([.. credentialId]));
		return Task.CompletedTask;
	}

	/// <summary>
	///     Materializes at most one whole user, both fragments, untracked, and attaches its as-read baseline. Every
	///     read that returns a <see cref="NorseUser" /> comes through here, and every one names exactly one subject.
	/// </summary>
	static async Task<NorseUser?> ReadAsync(IQueryable<NorseUser> query, CancellationToken cancellationToken)
	{
		var user = await query
			.AsNoTracking()
			.SingleOrDefaultAsync(cancellationToken)
			.ConfigureAwait(false);
		if (user is not null)
			_baselines.AddOrUpdate(user, UserBaseline.Capture(user));
		return user;
	}

	/// <summary>Appends <paramref name="intent" /> to the instance's staged intents (spec §4.3); the next flush drains them.</summary>
	static void Stage(NorseUser user, StagedIntent intent) =>
		_staged.GetOrCreateValue(user).Add(intent);

	/// <summary>
	///     Resolves a flush whose commit may have landed (spec §4.10). With a marker, the stamp is read on a fresh
	///     connection, never the failed transaction's: the new stamp means committed, so the baseline is refreshed and
	///     the flush succeeds; the baseline stamp means not committed, a definite failure (§4.8). Anything else -- no
	///     marker, a concurrent writer's stamp, or a read that failed -- stays indeterminate: the instance is poisoned
	///     and the flush answers <see cref="IndeterminateOutcomeErrorCode" />. Nothing is retried.
	/// </summary>
	async Task<IdentityResult> ResolveAsync((NorseUser User, UserBaseline Baseline, IReadOnlyList<StagedIntent> Intents) flush,
		string? marker, IndeterminateWriteException indeterminate)
	{
		var (user, baseline, intents) = flush;
		if (marker is not null && await StoredStampAsync(user.Id).ConfigureAwait(false) is (true, var stored))
		{
			if (string.Equals(stored, marker, StringComparison.Ordinal))
			{
				user.ConcurrencyStamp = marker;
				_baselines.AddOrUpdate(user, baseline.Refreshed(user).WithPasskeyIntents(intents));
				return IdentityResult.Success;
			}

			if (string.Equals(stored, baseline.ConcurrencyStamp, StringComparison.Ordinal))
			{
				baseline.Restore(user);
				ExceptionDispatchInfo.Throw(indeterminate.InnerException ?? indeterminate);
			}
		}

		Poison(user);
		return IdentityResult.Failed(new IdentityError
		{
			Code = IndeterminateOutcomeErrorCode,
			Description = "The change may or may not have been saved. Re-read the user before acting."
		});
	}

	/// <summary>
	///     The user's stored <c>concurrency_stamp</c>, read through a context of its own, so on a fresh connection.
	///     Never cancelled: the answer decides the outcome. A read that fails answers <c>Read = false</c>.
	/// </summary>
	async Task<(bool Read, string? Stamp)> StoredStampAsync(Guid userId)
	{
		var fresh = CommitBoundary.Fresh(context);
		await using (fresh.ConfigureAwait(false))
		{
			try
			{
				var stamps = await fresh.Users
					.AsNoTracking()
					.Where(u => u.Id == userId)
					.Select(static u => u.ConcurrencyStamp)
					.ToListAsync(CancellationToken.None)
					.ConfigureAwait(false);
				return (stamps.Count is 1, stamps.SingleOrDefault());
			}
			catch (Exception failure) when (failure is DbException or InvalidOperationException)
			{
				return (false, null);
			}
		}
	}

	/// <summary>
	///     Poisons the instance (spec §4.10): drops its baseline and staged intents, so <see cref="UpdateAsync" />
	///     refuses it until the caller re-reads.
	/// </summary>
	static void Poison(NorseUser user)
	{
		_baselines.Remove(user);
		_staged.Remove(user);
	}

	/// <summary>The id of the role carrying <paramref name="normalizedRoleName" />, if one does.</summary>
	Task<Guid?> FindRoleIdAsync(string normalizedRoleName, CancellationToken cancellationToken) =>
		context.Roles
			.AsNoTracking()
			.Where(r => r.NormalizedName == normalizedRoleName)
			.Select(static r => (Guid?)r.Id)
			.SingleOrDefaultAsync(cancellationToken);

	/// <summary>Adds passkey state to the instance's baseline; an instance without one stays without one.</summary>
	static void RecordPasskeys(NorseUser user, IEnumerable<NorseUserPasskey> passkeys)
	{
		if (_baselines.TryGetValue(user, out var baseline))
			_baselines.AddOrUpdate(user, baseline.WithPasskeys(passkeys));
	}

	static UserPasskeyInfo ToInfo(NorseUserPasskey passkey) =>
		new(passkey.CredentialId, passkey.Data.PublicKey, passkey.Data.CreatedAt, passkey.Data.SignCount,
			passkey.Data.Transports, passkey.Data.IsUserVerified, passkey.Data.IsBackupEligible, passkey.Data.IsBackedUp,
			passkey.Data.AttestationObject, passkey.Data.ClientDataJson)
		{
			Name = passkey.Data.Name,
			Aaguid = passkey.Data.Aaguid
		};

	/// <summary>
	///     The insert (spec §4.3): both fragments, then the child rows staged before create, inside one explicit
	///     transaction. Only the user's own entry is added -- never its navigation graph -- and it is detached again
	///     whatever happens, so the context is left tracking nothing.
	/// </summary>
	async Task<IdentityResult> InsertAsync((NorseUser User, IReadOnlyList<StagedIntent> Intents) create,
		CancellationToken cancellationToken)
	{
		var (user, intents) = create;
		var transaction = await context.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
		await using (transaction.ConfigureAwait(false))
		{
			var entry = context.Entry(user);
			entry.State = EntityState.Added;
			try
			{
				await context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
			}
			finally
			{
				entry.State = EntityState.Detached;
			}

			if (await new FlushExecutor(context, describer)
					.ApplyChildrenAsync(user.Id, intents, transaction, cancellationToken)
					.ConfigureAwait(false) is { } refused)
				return refused;

			await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
			return IdentityResult.Success;
		}
	}

	/// <summary>
	///     The increment's own transaction: one statement, then commit. The commit is the operation's observable
	///     boundary: a failure before it is definite, one during or after it is the commit-outcome case (§4.10).
	/// </summary>
	async Task<int> IncrementAsync(Guid userId, CancellationToken cancellationToken)
	{
		var transaction = await context.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
		await using (transaction.ConfigureAwait(false))
		{
			var count = await ProviderStatements
				.IncrementAccessFailedCountAsync(context, userId, cancellationToken)
				.ConfigureAwait(false);
			await CommitBoundary.CommitAsync(context, transaction, false, $"the access-failed increment for user {userId}", cancellationToken)
				.ConfigureAwait(false);
			return count;
		}
	}

	/// <summary>
	///     One redemption attempt's own transaction: the guarded swap, then commit, which is the attempt's
	///     observable boundary, as for the increment. A swap that matched nothing commits nothing worth keeping.
	/// </summary>
	async Task<int> SwapAsync(((Guid, string, string) Key, string Remaining, string Stored) swap,
		CancellationToken cancellationToken)
	{
		var transaction = await context.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
		await using (transaction.ConfigureAwait(false))
		{
			var rows = await ProviderStatements
				.SwapTokenAsync(context, swap.Key, swap.Remaining, swap.Stored, cancellationToken)
				.ConfigureAwait(false);
			await CommitBoundary.CommitAsync(context, transaction, false, $"a recovery-code redemption for user {swap.Key.Item1}", cancellationToken)
				.ConfigureAwait(false);
			return rows;
		}
	}
}
