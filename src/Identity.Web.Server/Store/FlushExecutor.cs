using System.Data.Common;
using System.Diagnostics;
using System.Runtime.ExceptionServices;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Query;
using Microsoft.EntityFrameworkCore.Storage;
using Norse.Identity.EntityFramework;
using Norse.Identity.Outcomes;

namespace Norse.Identity.Web.Server.Store;

/// <summary>
///     One flush (2026-10-24 explicit-writes spec §4.3): the plaintext diff of an instance against its as-read
///     baseline (§4.2), then the <c>users</c> statement, the credentials statement and one statement per staged
///     child-row intent (§4.6), in staging order, inside one explicit transaction, then commit. It writes nothing to
///     the instance but the new stamp, and only once the commit is acknowledged; restoring a failed instance and
///     refreshing a committed one's baseline belong to the store.
/// </summary>
/// <remarks>
///     It runs under the store's zero-retry strategy and never retries. The commit goes through
///     <see cref="CommitBoundary" />, which separates the two failure contracts: any exception but
///     <see cref="IndeterminateWriteException" /> is a definite failure, which rolled everything back (§4.8); that one is
///     the commit-outcome case (§4.10), which <see cref="Marker" /> resolves where the flush wrote <c>users</c>.
/// </remarks>
/// <param name="context">The Identity database context.</param>
/// <param name="describer">The source of the <see cref="IdentityError" />s a refused flush answers.</param>
sealed class FlushExecutor(NorseIdentityDbContext context, IdentityErrorDescriber describer)
{
	/// <summary>The savepoint a conflict-prone statement runs under, so its conflict can be read inside the transaction.</summary>
	const string ConflictSavepoint = "norse_child_conflict";

	/// <summary>
	///     The stamp marker (spec §4.10): the new <c>concurrency_stamp</c> once the <c>users</c> statement has run,
	///     which a lost acknowledgement is verified against. <see langword="null" /> when the flush wrote no
	///     <c>users</c> column, so no marker exists.
	/// </summary>
	public string? Marker { get; private set; }

	/// <summary>
	///     Diffs and, when anything changed, writes. A failed guard or a username taken in a race rolls back and
	///     answers a failed result; any other failure rolls back and throws.
	/// </summary>
	/// <param name="flush">The instance, its as-read baseline, and the intents staged against it.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	public async Task<IdentityResult> FlushAsync((NorseUser User, UserBaseline Baseline, IReadOnlyList<StagedIntent> Intents) flush,
		CancellationToken cancellationToken = default)
	{
		var (user, baseline, intents) = flush;
		var usersChanges = UsersChanges(user, baseline);
		var usersChanged = usersChanges.Count is not 0;
		var (assignments, guards) = CredentialsChanges(user, baseline, intents);
		List<StagedIntent> children = [.. intents.Where(static intent => intent is not StagedIntent.ResetAccessFailedCount)];
		if (!usersChanged && assignments.Count is 0 && children.Count is 0)
			return IdentityResult.Success;

		var newStamp = Guid.NewGuid().ToString();
		var transaction = await context.Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
		await using (transaction.ConfigureAwait(false))
		{
			// A zero-row users statement under a real diff means the stamp moved (no probe: a no-op never issues it).
			if (usersChanged)
			{
				if (await UpdateUsersAsync(user.Id, baseline, usersChanges, newStamp, cancellationToken).ConfigureAwait(false) is not 1)
				{
					await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
					return IdentityResult.Failed(describer.ConcurrencyFailure());
				}

				Marker = newStamp;
			}

			if (assignments.Count is not 0)
			{
				int rows;
				try
				{
					rows = await ProviderStatements
						.UpdateCredentialsAsync(context, user.Id, assignments, guards, cancellationToken)
						.ConfigureAwait(false);
				}
				catch (DbException) when (!string.Equals(user.NormalizedUserName, baseline.NormalizedUserName, StringComparison.Ordinal))
				{
					// A race past UserValidator. On PostgreSQL the violation has aborted the transaction (PoC G4), so
					// roll back before reading anything; the read then tells a taken username from any other failure.
					await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
					if (await UserNameTakenAsync(user, cancellationToken).ConfigureAwait(false))
						return IdentityResult.Failed(describer.DuplicateUserName(user.UserName ?? string.Empty));

					throw;
				}

				if (rows is not 1)
				{
					await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
					return IdentityResult.Failed(describer.ConcurrencyFailure());
				}
			}

			if (await ApplyChildrenAsync(user.Id, children, transaction, cancellationToken).ConfigureAwait(false) is { } refused)
				return refused;

			await CommitBoundary.CommitAsync(context, transaction, Marker is not null, $"the flush for user {user.Id}", cancellationToken).ConfigureAwait(false);
		}

		if (usersChanged)
			user.ConcurrencyStamp = newStamp;
		return IdentityResult.Success;
	}

	/// <summary>
	///     The child-row statements (spec §4.6): one per intent, in staging order, inside <paramref name="transaction" />.
	///     An intent the database refuses -- a foreign login or passkey, a moved claim, a newer or removed passkey --
	///     rolls the whole transaction back and answers the failure; <see langword="null" /> means every one applied.
	/// </summary>
	/// <param name="userId">The user the intents were staged against.</param>
	/// <param name="intents">The child-row intents, in staging order.</param>
	/// <param name="transaction">The flush's (or the create's) transaction.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	public async Task<IdentityResult?> ApplyChildrenAsync(Guid userId, IReadOnlyList<StagedIntent> intents,
		IDbContextTransaction transaction, CancellationToken cancellationToken = default)
	{
		foreach (var intent in intents)
		{
			if (await ApplyAsync(userId, intent, transaction, cancellationToken).ConfigureAwait(false) is not { } error)
				continue;

			await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
			return IdentityResult.Failed(error);
		}

		return null;
	}

	/// <summary>One intent's statement; the error it answers when the database refuses it, or <see langword="null" />.</summary>
	Task<IdentityError?> ApplyAsync(Guid userId, StagedIntent intent, IDbContextTransaction transaction,
		CancellationToken cancellationToken) =>
		intent switch
		{
			// Carried by the credentials statement, or, before create, by the inserted row itself.
			StagedIntent.ResetAccessFailedCount => Task.FromResult<IdentityError?>(null),
			StagedIntent.AddClaim(var type, var value) =>
				AppliedAsync(ProviderStatements.InsertClaimIfAbsentAsync(context, userId, type, value, cancellationToken)),
			StagedIntent.ReplaceClaim replace => ReplaceClaimAsync(userId, replace, transaction, cancellationToken),
			StagedIntent.RemoveClaim(var type, var value) =>
				AppliedAsync(ProviderStatements.DeleteClaimAsync(context, userId, (type, value), cancellationToken)),
			StagedIntent.AddLogin login => AddLoginAsync(userId, login, transaction, cancellationToken),
			StagedIntent.RemoveLogin removal => RemoveLoginAsync(userId, removal, cancellationToken),
			StagedIntent.AddRole(var roleId) =>
				AppliedAsync(ProviderStatements.InsertRoleIfAbsentAsync(context, userId, roleId, cancellationToken)),
			StagedIntent.RemoveRole(var roleId) => AppliedAsync(context.UserRoles
				.Where(r => r.UserId == userId && r.RoleId == roleId)
				.ExecuteDeleteAsync(cancellationToken)),
			StagedIntent.UpsertToken(var loginProvider, var name, var value) =>
				AppliedAsync(ProviderStatements.UpsertTokenAsync(context, (userId, loginProvider, name), value,
					cancellationToken: cancellationToken)),
			StagedIntent.InsertTokenIfAbsent(var loginProvider, var name, var value) =>
				AppliedAsync(ProviderStatements.UpsertTokenAsync(context, (userId, loginProvider, name), value, onlyIfAbsent: true,
					cancellationToken)),
			StagedIntent.RemoveToken(var loginProvider, var name) => AppliedAsync(context.UserTokens
				.Where(t => t.UserId == userId && t.LoginProvider == loginProvider && t.Name == name)
				.ExecuteDeleteAsync(cancellationToken)),
			StagedIntent.EnrollPasskey enrollment => EnrollPasskeyAsync(userId, enrollment, transaction, cancellationToken),
			StagedIntent.UpdatePasskey update => UpdatePasskeyAsync(userId, update, cancellationToken),
			StagedIntent.RemovePasskey(var credentialId) => AppliedAsync(context.UserPasskeys
				.Where(p => p.UserId == userId && p.CredentialId.SequenceEqual(credentialId))
				.ExecuteDeleteAsync(cancellationToken)),
			_ => throw new UnreachableException($"{intent.GetType().Name} has no statement.")
		};

	/// <summary>
	///     Replace (spec §4.6; converging ruled 2026-10-25). Claims are a set, so the statements are ordered to end as
	///     exactly the new claim B whatever a concurrent writer does:
	///     <list type="number">
	///         <item>
	///             rewrite A to B where the user does not already hold B, under a savepoint: if a concurrent add of B
	///             commits first, the rewrite collides with the unique key, and the savepoint keeps the transaction
	///             usable (PostgreSQL aborts it otherwise, PoC G4);
	///         </item>
	///         <item>
	///             delete A where the user holds B: after a rewrite A is gone, so this is a no-op; otherwise it is the
	///             converge, and as a fresh statement it sees a B committed after step 1 began.
	///         </item>
	///     </list>
	///     Neither statement ever removes B, and a concurrent add of B only ever meets B. Zero rows from both is the
	///     replay rule: B present is success, B absent means A moved, a concurrency failure.
	/// </summary>
	async Task<IdentityError?> ReplaceClaimAsync(Guid userId, StagedIntent.ReplaceClaim replace, IDbContextTransaction transaction,
		CancellationToken cancellationToken)
	{
		(string, string)
			claim = (replace.Type, replace.Value),
			replacement = (replace.NewType, replace.NewValue);
		var rewritten = 0;
		var collision = await TryStatementAsync(transaction, async () => rewritten = await ProviderStatements
			.ReplaceClaimAsync(context, userId, claim, replacement, cancellationToken)
			.ConfigureAwait(false), cancellationToken).ConfigureAwait(false);
		if (rewritten is not 0 || await ProviderStatements
				.DeleteReplacedClaimAsync(context, userId, claim, replacement, cancellationToken)
				.ConfigureAwait(false) is not 0)
			return null;

		if (await ProviderStatements.ClaimExistsAsync(context, userId, replacement, cancellationToken).ConfigureAwait(false))
			return null;

		// A rewrite that failed with no B behind it was no collision: never pass that off as a concurrency failure.
		if (collision is not null)
			ExceptionDispatchInfo.Throw(collision);
		return describer.ConcurrencyFailure();
	}

	/// <summary>Add login (spec §4.6): a conflict with the same user's row is a replay; one with another user's fails.</summary>
	async Task<IdentityError?> AddLoginAsync(Guid userId, StagedIntent.AddLogin login, IDbContextTransaction transaction,
		CancellationToken cancellationToken)
	{
		if (await TryStatementAsync(transaction, () => ProviderStatements.InsertLoginAsync(context, userId, login, cancellationToken),
				cancellationToken).ConfigureAwait(false) is not { } conflict)
			return null;

		var owner = await context.UserLogins
			.AsNoTracking()
			.Where(l => l.LoginProvider == login.LoginProvider && l.ProviderKey == login.ProviderKey)
			.Select(static l => (Guid?)l.UserId)
			.SingleOrDefaultAsync(cancellationToken)
			.ConfigureAwait(false);
		if (owner is null)
			ExceptionDispatchInfo.Throw(conflict);
		return owner == userId ?
			null :
			describer.LoginAlreadyAssociated();
	}

	/// <summary>
	///     Remove login, guarded by the last sign-in method rule (2026-10-26 account-lifecycle spec §5.9): a user keeps a
	///     password or at least one external login. The user's credentials row is locked and its password read, the
	///     logins that would remain counted, and a removal that would leave neither is refused; the caller rolls back.
	///     Removing a login the user doesn't have leaves one remaining as before, so it stays a no-op.
	/// </summary>
	/// <remarks>
	///     On the manager path the stamp CAS on <c>user_credentials</c> (step 2 of the flush) already serializes two
	///     stale instances: the second's credentials statement blocks on the row and then matches zero rows
	///     (<c>ConcurrencyFailure</c>). The lock here serializes any flush the CAS does not cover -- a store flush with
	///     no stamp change -- so the count it reads is authoritative.
	/// </remarks>
	async Task<IdentityError?> RemoveLoginAsync(Guid userId, StagedIntent.RemoveLogin intent, CancellationToken cancellationToken)
	{
		var hasPassword = await ProviderStatements.HasPasswordForUpdateAsync(context, userId, cancellationToken).ConfigureAwait(false);
		var (loginProvider, providerKey) = intent;
		var remaining = await context.UserLogins
			.CountAsync(l => l.UserId == userId && !(l.LoginProvider == loginProvider && l.ProviderKey == providerKey), cancellationToken)
			.ConfigureAwait(false);
		if (!hasPassword && remaining is 0)
			return new()
			{
				Code = NorseUserStore.LastSignInMethodErrorCode,
				Description = "This is the only way to sign in to your account."
			};

		await context.UserLogins
			.Where(l => l.UserId == userId && l.LoginProvider == loginProvider && l.ProviderKey == providerKey)
			.ExecuteDeleteAsync(cancellationToken)
			.ConfigureAwait(false);
		return null;
	}

	/// <summary>
	///     Enrollment (spec §4.6): a conflict on the credential id with an identical row -- same user, same public key
	///     -- is a replay; any other conflict fails.
	/// </summary>
	async Task<IdentityError?> EnrollPasskeyAsync(Guid userId, StagedIntent.EnrollPasskey enrollment, IDbContextTransaction transaction,
		CancellationToken cancellationToken)
	{
		if (await TryStatementAsync(transaction, () => InsertPasskeyAsync(userId, enrollment, cancellationToken), cancellationToken)
				.ConfigureAwait(false) is not { } conflict)
			return null;

		var credentialId = enrollment.CredentialId;
		var existing = await context.UserPasskeys
			.AsNoTracking()
			.SingleOrDefaultAsync(p => p.CredentialId.SequenceEqual(credentialId), cancellationToken)
			.ConfigureAwait(false);
		if (existing is null)
			ExceptionDispatchInfo.Throw(conflict);
		return existing.UserId == userId && existing.Data.PublicKey.AsSpan().SequenceEqual(enrollment.Data.PublicKey) ?
			null :
			new()
			{
				Code = NorseUserStore.PasskeyAlreadyRegisteredErrorCode,
				Description = "The passkey is already registered."
			};
	}

	/// <summary>
	///     The assertion update (spec §4.6): guarded by the as-read sign count, never an insert. Zero rows -- a newer
	///     count committed, or the credential was removed -- fails, so sign-in fails closed.
	/// </summary>
	async Task<IdentityError?> UpdatePasskeyAsync(Guid userId, StagedIntent.UpdatePasskey update, CancellationToken cancellationToken) =>
		await ProviderStatements.UpdatePasskeyAsync(context, userId, update, cancellationToken).ConfigureAwait(false) is 1 ?
			null :
			describer.ConcurrencyFailure();

	/// <summary>
	///     The enrollment's one statement: EF's single-row <c>INSERT</c> into <c>user_passkeys</c>, the statement PoC G4
	///     proved, issued through <c>SaveChanges</c> because the passkey document is EF's JSON mapping and only EF writes
	///     that document. Only the passkey's own entry is added -- never a graph -- and it is detached again whatever
	///     happens, so the context is left tracking nothing.
	/// </summary>
	async Task<int> InsertPasskeyAsync(Guid userId, StagedIntent.EnrollPasskey enrollment, CancellationToken cancellationToken)
	{
		var entry = context.Entry(new NorseUserPasskey { CredentialId = enrollment.CredentialId, UserId = userId, Data = enrollment.Data });
		entry.State = EntityState.Added;
		try
		{
			return await context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
		}
		finally
		{
			entry.State = EntityState.Detached;
		}
	}

	/// <summary>
	///     Runs a conflict-prone statement under a savepoint. On failure the transaction is rolled back to just before
	///     the statement -- on PostgreSQL the violation has aborted it (PoC G4), so nothing can be read until then -- and
	///     the failure is returned for the caller to classify by reading the conflicting row.
	/// </summary>
	static async Task<Exception?> TryStatementAsync(IDbContextTransaction transaction, Func<Task<int>> statement,
		CancellationToken cancellationToken)
	{
		await transaction.CreateSavepointAsync(ConflictSavepoint, cancellationToken).ConfigureAwait(false);
		try
		{
			await statement().ConfigureAwait(false);
		}
		catch (Exception conflict) when (conflict is DbException or DbUpdateException { InnerException: DbException })
		{
			await transaction.RollbackToSavepointAsync(ConflictSavepoint, cancellationToken).ConfigureAwait(false);
			return conflict;
		}

		await transaction.ReleaseSavepointAsync(ConflictSavepoint, cancellationToken).ConfigureAwait(false);
		return null;
	}

	/// <summary>A statement no outcome of which is a refusal: its row count carries no decision.</summary>
	static async Task<IdentityError?> AppliedAsync(Task<int> statement)
	{
		await statement.ConfigureAwait(false);
		return null;
	}

	/// <summary>
	///     The <c>users</c> diff, the one place it is computed: a setter for each <c>users</c> column that differs
	///     from the baseline, ordinal for strings and value equality otherwise. Empty means the statement is never
	///     issued.
	/// </summary>
	static List<Action<UpdateSettersBuilder<NorseUser>>> UsersChanges(NorseUser user, UserBaseline baseline)
	{
		List<Action<UpdateSettersBuilder<NorseUser>>> changes = [];
		if (!string.Equals(user.UserName, baseline.UserName, StringComparison.Ordinal))
			changes.Add(setters => setters.SetProperty(static u => u.UserName, user.UserName));
		if (!string.Equals(user.Email, baseline.Email, StringComparison.Ordinal))
			changes.Add(setters => setters.SetProperty(static u => u.Email, user.Email));
		if (user.EmailConfirmed != baseline.EmailConfirmed)
			changes.Add(setters => setters.SetProperty(static u => u.EmailConfirmed, user.EmailConfirmed));
		if (!string.Equals(user.PhoneNumber, baseline.PhoneNumber, StringComparison.Ordinal))
			changes.Add(setters => setters.SetProperty(static u => u.PhoneNumber, user.PhoneNumber));
		if (user.PhoneNumberConfirmed != baseline.PhoneNumberConfirmed)
			changes.Add(setters => setters.SetProperty(static u => u.PhoneNumberConfirmed, user.PhoneNumberConfirmed));
		if (user.TwoFactorEnabled != baseline.TwoFactorEnabled)
			changes.Add(setters => setters.SetProperty(static u => u.TwoFactorEnabled, user.TwoFactorEnabled));
		if (user.LockoutEnabled != baseline.LockoutEnabled)
			changes.Add(setters => setters.SetProperty(static u => u.LockoutEnabled, user.LockoutEnabled));
		return changes;
	}

	/// <summary>
	///     The credentials statement's columns and guards, per spec §4.4: the password hash and security stamp swap
	///     together against their baselines, as do the two lookup hashes; a lockout end and an access-count reset are
	///     unconditional value writes.
	/// </summary>
	static (List<(string Property, object? Value)> Assignments, List<(string Property, object? Baseline)> Guards) CredentialsChanges(
		NorseUser user, UserBaseline baseline, IReadOnlyList<StagedIntent> intents)
	{
		List<(string Property, object? Value)> assignments = [];
		List<(string Property, object? Baseline)> guards = [];
		bool
			passwordHash = !string.Equals(user.PasswordHash, baseline.PasswordHash, StringComparison.Ordinal),
			securityStamp = !string.Equals(user.SecurityStamp, baseline.SecurityStamp, StringComparison.Ordinal),
			normalizedEmail = !string.Equals(user.NormalizedEmail, baseline.NormalizedEmail, StringComparison.Ordinal),
			normalizedUserName = !string.Equals(user.NormalizedUserName, baseline.NormalizedUserName, StringComparison.Ordinal);

		if (passwordHash)
			assignments.Add((nameof(NorseUser.PasswordHash), user.PasswordHash));
		if (securityStamp)
			assignments.Add((nameof(NorseUser.SecurityStamp), user.SecurityStamp));
		if (passwordHash || securityStamp)
			guards.AddRange([
				(nameof(NorseUser.PasswordHash), baseline.PasswordHash),
				(nameof(NorseUser.SecurityStamp), baseline.SecurityStamp)
			]);

		if (normalizedEmail)
			assignments.Add((nameof(NorseUser.NormalizedEmail), user.NormalizedEmail));
		if (normalizedUserName)
			assignments.Add((nameof(NorseUser.NormalizedUserName), user.NormalizedUserName));
		if (normalizedEmail || normalizedUserName)
			guards.AddRange([
				(nameof(NorseUser.NormalizedEmail), baseline.NormalizedEmail),
				(nameof(NorseUser.NormalizedUserName), baseline.NormalizedUserName)
			]);

		if (intents.Any(static intent => intent is StagedIntent.ResetAccessFailedCount) ||
			user.AccessFailedCount != baseline.AccessFailedCount)
			assignments.Add((nameof(NorseUser.AccessFailedCount), user.AccessFailedCount));
		if (user.LockoutEnd != baseline.LockoutEnd)
			assignments.Add((nameof(NorseUser.LockoutEnd), user.LockoutEnd));
		return (assignments, guards);
	}

	/// <summary>
	///     The <c>users</c> statement (spec §4.3 step 1): only the changed columns (<paramref name="changes" />)
	///     and the new stamp, guarded by the baseline stamp. Through <c>ExecuteUpdate</c>, which touches <c>users</c> alone (PoC G1); the personal-data
	///     converters encrypt the changed values here, under the caller's crypto scope.
	/// </summary>
	Task<int> UpdateUsersAsync(Guid id, UserBaseline baseline, List<Action<UpdateSettersBuilder<NorseUser>>> changes,
		string newStamp, CancellationToken cancellationToken)
	{
		var baselineStamp = baseline.ConcurrencyStamp;
		return context.Users
			.Where(u => u.Id == id && u.ConcurrencyStamp == baselineStamp)
			.ExecuteUpdateAsync(setters =>
			{
				foreach (var change in changes)
					change(setters);
				setters.SetProperty(static u => u.ConcurrencyStamp, newStamp);
			}, cancellationToken);
	}

	/// <summary>Whether another user now holds the user name hash this flush tried to take. Read after the rollback.</summary>
	Task<bool> UserNameTakenAsync(NorseUser user, CancellationToken cancellationToken)
	{
		var id = user.Id;
		var normalizedUserName = user.NormalizedUserName;
		return context.Users
			.AsNoTracking()
			.AnyAsync(u => u.Id != id && u.NormalizedUserName == normalizedUserName, cancellationToken);
	}
}
