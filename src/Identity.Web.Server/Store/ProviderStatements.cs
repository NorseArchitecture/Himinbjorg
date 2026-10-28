using System.Data.Common;
using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Norse.Identity.EntityFramework;
using Norse.Persistence.EntityFramework;

namespace Norse.Identity.Web.Server.Store;

/// <summary>
///     The store's raw statements, one spelling per provider (2026-10-24 explicit-writes spec §12, G1, ruled
///     2026-10-24). EF can't issue a credentials statement against the <c>user_credentials</c> fragment alone: its
///     <c>ExecuteUpdate</c> always joins the principal through the shared key (PoC G1). So every
///     <c>user_credentials</c> statement is written here, against that one table, and the provider is picked the way
///     <see cref="NorseIdentityDbContext" /> picks it, by <c>Database.ProviderName</c>. The immediate operations
///     (§4.5) live here too: the increment needs a value back from its <c>UPDATE</c>, which <c>ExecuteUpdate</c>
///     can't return, and the recovery-code swap must guard on the stored ciphertext, which a converted parameter
///     never reproduces.
/// </summary>
/// <remarks>
///     Only identifiers and parameter names are ever interpolated into the text; every value travels as a
///     parameter built from the model's own type mapping for its property, so a value converter (the password hash
///     is stored as bytes; a token value is encrypted) and the column's store type apply exactly as EF would apply
///     them, and a <see langword="null" /> carries its type (SQL Server refuses an untyped <c>NULL</c> against
///     <c>varbinary</c>). The one exception is a guard on a value exactly as stored, bound with the column's store
///     type and no converter.
/// </remarks>
static class ProviderStatements
{
	static readonly Dialect _postgreSql = new(
		new("user_credentials", new Dictionary<string, string>
		{
			[nameof(NorseUser.Id)] = "id",
			[nameof(NorseUser.PasswordHash)] = "password_hash",
			[nameof(NorseUser.SecurityStamp)] = "security_stamp",
			[nameof(NorseUser.NormalizedEmail)] = "normalized_email",
			[nameof(NorseUser.NormalizedUserName)] = "normalized_user_name",
			[nameof(NorseUser.AccessFailedCount)] = "access_failed_count",
			[nameof(NorseUser.LockoutEnd)] = "lockout_end"
		}),
		new("user_tokens", new Dictionary<string, string>
		{
			[nameof(NorseUserToken.UserId)] = "user_id",
			[nameof(NorseUserToken.LoginProvider)] = "login_provider",
			[nameof(NorseUserToken.Name)] = "name",
			[nameof(NorseUserToken.Value)] = "value"
		}),
		new("user_claims", new Dictionary<string, string>
		{
			[nameof(NorseUserClaim.Id)] = "id",
			[nameof(NorseUserClaim.UserId)] = "user_id",
			[nameof(NorseUserClaim.ClaimType)] = "claim_type",
			[nameof(NorseUserClaim.ClaimValue)] = "claim_value",
			[NorseUserClaim.ClaimValueHash] = "claim_value_hash"
		}),
		new("user_logins", new Dictionary<string, string>
		{
			[nameof(NorseUserLogin.LoginProvider)] = "login_provider",
			[nameof(NorseUserLogin.ProviderKey)] = "provider_key",
			[nameof(NorseUserLogin.ProviderDisplayName)] = "provider_display_name",
			[nameof(NorseUserLogin.UserId)] = "user_id"
		}),
		new("user_roles", new Dictionary<string, string>
		{
			[nameof(NorseUserRole.UserId)] = "user_id",
			[nameof(NorseUserRole.RoleId)] = "role_id"
		}),
		new("user_passkeys", new Dictionary<string, string>
		{
			[nameof(NorseUserPasskey.CredentialId)] = "credential_id",
			[nameof(NorseUserPasskey.UserId)] = "user_id",
			[nameof(NorseUserPasskey.Data)] = "data"
		}),
		"\"Value\"",
		"RETURNING {0}",
		"",
		"",
		// The chassis-owned IMMUTABLE wrapper the generated column itself uses (spec §4.6, PoC G6).
		"norse_utf8_sha256({0})",
		"({0} ->> 'SignCount')::bigint",
		// jsonb || object replaces exactly the named keys; typed parameters, so a null name is a JSON null.
		"{0} || jsonb_build_object('Name', {1}, 'SignCount', {2}, 'IsUserVerified', {3}, 'IsBackedUp', {4})",
		false,
		"",
		" FOR UPDATE");

	static readonly Dialect _sqlServer = new(
		new("[UserCredentials]", new Dictionary<string, string>
		{
			[nameof(NorseUser.Id)] = "[Id]",
			[nameof(NorseUser.PasswordHash)] = "[PasswordHash]",
			[nameof(NorseUser.SecurityStamp)] = "[SecurityStamp]",
			[nameof(NorseUser.NormalizedEmail)] = "[NormalizedEmail]",
			[nameof(NorseUser.NormalizedUserName)] = "[NormalizedUserName]",
			[nameof(NorseUser.AccessFailedCount)] = "[AccessFailedCount]",
			[nameof(NorseUser.LockoutEnd)] = "[LockoutEnd]"
		}),
		new("[UserTokens]", new Dictionary<string, string>
		{
			[nameof(NorseUserToken.UserId)] = "[UserId]",
			[nameof(NorseUserToken.LoginProvider)] = "[LoginProvider]",
			[nameof(NorseUserToken.Name)] = "[Name]",
			[nameof(NorseUserToken.Value)] = "[Value]"
		}),
		new("[UserClaims]", new Dictionary<string, string>
		{
			[nameof(NorseUserClaim.Id)] = "[Id]",
			[nameof(NorseUserClaim.UserId)] = "[UserId]",
			[nameof(NorseUserClaim.ClaimType)] = "[ClaimType]",
			[nameof(NorseUserClaim.ClaimValue)] = "[ClaimValue]",
			[NorseUserClaim.ClaimValueHash] = "[ClaimValueHash]"
		}),
		new("[UserLogins]", new Dictionary<string, string>
		{
			[nameof(NorseUserLogin.LoginProvider)] = "[LoginProvider]",
			[nameof(NorseUserLogin.ProviderKey)] = "[ProviderKey]",
			[nameof(NorseUserLogin.ProviderDisplayName)] = "[ProviderDisplayName]",
			[nameof(NorseUserLogin.UserId)] = "[UserId]"
		}),
		new("[UserRoles]", new Dictionary<string, string>
		{
			[nameof(NorseUserRole.UserId)] = "[UserId]",
			[nameof(NorseUserRole.RoleId)] = "[RoleId]"
		}),
		new("[UserPasskeys]", new Dictionary<string, string>
		{
			[nameof(NorseUserPasskey.CredentialId)] = "[CredentialId]",
			[nameof(NorseUserPasskey.UserId)] = "[UserId]",
			[nameof(NorseUserPasskey.Data)] = "[Data]"
		}),
		"[Value]",
		"",
		"OUTPUT inserted.{0}",
		// Ciphertext is compared byte for byte; the database's default collation folds case.
		" COLLATE Latin1_General_100_BIN2",
		// The computed column's own expression, over nvarchar(max) so the input bytes are UTF-16LE like the
		// column's (PoC G6: a varchar of the same text hashes differently).
		"CAST(HASHBYTES('SHA2_256', CAST({0} AS nvarchar(max))) AS binary(32))",
		"JSON_VALUE({0}, '$.SignCount' RETURNING bigint)",
		// EF's own spelling of a JSON property update on SQL Server 2025; a null name drops the key, which reads back
		// as null.
		"JSON_MODIFY(JSON_MODIFY(JSON_MODIFY(JSON_MODIFY({0}, '$.Name', {1}), '$.SignCount', {2}), '$.IsUserVerified', {3}), '$.IsBackedUp', {4})",
		true,
		" WITH (UPDLOCK, HOLDLOCK)",
		"");

	/// <summary>
	///     The credentials statement (spec §4.3 step 2, §4.4): one <c>UPDATE</c> of the user's
	///     <c>user_credentials</c> row, setting <paramref name="assignments" /> where every one of
	///     <paramref name="guards" /> still holds its baseline value. A nullable column is compared with
	///     <c>IS NOT DISTINCT FROM</c>, so a <see langword="null" /> baseline guards too.
	/// </summary>
	/// <param name="context">The context, inside the flush's transaction.</param>
	/// <param name="userId">The user.</param>
	/// <param name="assignments">The columns to set, by <see cref="NorseUser" /> property name, with their new values.</param>
	/// <param name="guards">The compare-and-swap predicates, by property name, with their baseline values.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>The number of rows matched: 1, or 0 when a guard failed.</returns>
	public static Task<int> UpdateCredentialsAsync(NorseIdentityDbContext context, Guid userId,
		IReadOnlyList<(string Property, object? Value)> assignments, IReadOnlyList<(string Property, object? Baseline)> guards,
		CancellationToken cancellationToken = default)
	{
		var credentials = DialectOf(context).Credentials;
		using Binder bind = new(context, context.Users.EntityType);

		string Guard(string property, object? baseline)
		{
			var comparison = bind.Entity.GetProperty(property).IsNullable ?
				"IS NOT DISTINCT FROM" :
				"=";
			return $"{credentials.Columns[property]} {comparison} {bind.Value(property, baseline)}";
		}

		var set = string.Join(", ", assignments.Select(assignment =>
			$"{credentials.Columns[assignment.Property]} = {bind.Value(assignment.Property, assignment.Value)}"));
		var where = string.Join(" AND ", [
			$"{credentials.Columns[nameof(NorseUser.Id)]} = {bind.Value(nameof(NorseUser.Id), userId)}",
			.. guards.Select(guard => Guard(guard.Property, guard.Baseline))
		]);
		var sql = $"""
			UPDATE {credentials.Name}
			SET {set}
			WHERE {where}
			""";
		return context.Database.ExecuteSqlRawAsync(sql, bind.Parameters, cancellationToken);
	}

	/// <summary>
	///     The increment (spec §4.5): <c>access_failed_count + 1</c> on the user's <c>user_credentials</c> row,
	///     returning the new count from the same statement (<c>RETURNING</c> / <c>OUTPUT</c>). The query stays
	///     uncomposed and is materialized as a list: composing it (<c>Single()</c>) would wrap the <c>UPDATE</c> in a
	///     subquery (PoC G1).
	/// </summary>
	/// <param name="context">The context, inside the increment's own transaction.</param>
	/// <param name="userId">The user.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>The new count.</returns>
	/// <exception cref="InvalidOperationException">The user has no credentials row.</exception>
	public static async Task<int> IncrementAccessFailedCountAsync(NorseIdentityDbContext context, Guid userId,
		CancellationToken cancellationToken = default)
	{
		var dialect = DialectOf(context);
		var credentials = dialect.Credentials;
		using Binder bind = new(context, context.Users.EntityType);
		var count = credentials.Columns[nameof(NorseUser.AccessFailedCount)];
		var returned = $"{count} AS {dialect.ValueAlias}";
		string[] lines =
		[
			$"UPDATE {credentials.Name}",
			$"SET {count} = {count} + 1",
			string.Format(CultureInfo.InvariantCulture, dialect.Output, returned),
			$"WHERE {credentials.Columns[nameof(NorseUser.Id)]} = {bind.Value(nameof(NorseUser.Id), userId)}",
			string.Format(CultureInfo.InvariantCulture, dialect.Returning, returned)
		];
		var sql = string.Join('\n', lines.Where(static line => line.Length is not 0));
		var counts = await context.Database
			.SqlQueryRaw<int>(sql, [.. bind.Parameters])
			.ToListAsync(cancellationToken)
			.ConfigureAwait(false);
		return counts is [var newCount] ?
			newCount :
			throw new InvalidOperationException($"User {userId} has no credentials row to count a failed attempt against.");
	}

	/// <summary>
	///     Whether the user has a password (2026-10-26 account-lifecycle spec §5.9), read under an update lock on the
	///     user's <c>user_credentials</c> row that is held to the end of the transaction (<c>FOR UPDATE</c> /
	///     <c>WITH (UPDLOCK, HOLDLOCK)</c>), so a concurrent flush for the same user waits for this one.
	/// </summary>
	/// <param name="context">The context, inside the flush's transaction.</param>
	/// <param name="userId">The user.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>Whether the stored password hash is non-null.</returns>
	/// <exception cref="InvalidOperationException">The user has no credentials row.</exception>
	public static async Task<bool> HasPasswordForUpdateAsync(NorseIdentityDbContext context, Guid userId,
		CancellationToken cancellationToken = default)
	{
		var dialect = DialectOf(context);
		var credentials = dialect.Credentials;
		using Binder bind = new(context, context.Users.EntityType);
		var sql = $"""
			SELECT CASE WHEN {credentials.Columns[nameof(NorseUser.PasswordHash)]} IS NULL THEN 0 ELSE 1 END AS {dialect.ValueAlias}
			FROM {credentials.Name}{dialect.LockHint}
			WHERE {credentials.Columns[nameof(NorseUser.Id)]} = {bind.Value(nameof(NorseUser.Id), userId)}{dialect.LockSuffix}
			""";
		var values = await context.Database
			.SqlQueryRaw<int>(sql, [.. bind.Parameters])
			.ToListAsync(cancellationToken)
			.ConfigureAwait(false);
		return values is [var value] ?
			value is 1 :
			throw new InvalidOperationException($"User {userId} has no credentials row to read a password from.");
	}

	/// <summary>
	///     One token's value exactly as stored (ciphertext, when personal data is protected), for a compare-and-swap
	///     guard: the value converter is bypassed, since re-encrypting a value never reproduces the stored bytes.
	/// </summary>
	/// <param name="context">The context.</param>
	/// <param name="key">The token's key.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>Whether the row exists, and its stored value.</returns>
	public static async Task<(bool Exists, string? Stored)> ReadStoredTokenAsync(NorseIdentityDbContext context,
		(Guid UserId, string LoginProvider, string Name) key, CancellationToken cancellationToken = default)
	{
		var dialect = DialectOf(context);
		var tokens = dialect.Tokens;
		using Binder bind = new(context, context.UserTokens.EntityType);
		var sql = $"""
			SELECT {tokens.Columns[nameof(NorseUserToken.Value)]} AS {dialect.ValueAlias}
			FROM {tokens.Name}
			WHERE {TokenKey(tokens, bind, key)}
			""";
		var stored = await context.Database
			.SqlQueryRaw<string?>(sql, [.. bind.Parameters])
			.ToListAsync(cancellationToken)
			.ConfigureAwait(false);
		return stored is [var value] ?
			(true, value) :
			(false, null);
	}

	/// <summary>
	///     The token compare-and-swap (spec §4.5, recovery-code redemption): sets the token to
	///     <paramref name="value" /> (through the model's converter, so it is encrypted) where it still holds
	///     <paramref name="stored" />, exactly as read by <see cref="ReadStoredTokenAsync" />.
	/// </summary>
	/// <param name="context">The context, inside the attempt's own transaction.</param>
	/// <param name="key">The token's key.</param>
	/// <param name="value">The new plaintext value.</param>
	/// <param name="stored">The stored value the swap is guarded by.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>The number of rows matched: 1, or 0 when the value moved.</returns>
	public static Task<int> SwapTokenAsync(NorseIdentityDbContext context, (Guid UserId, string LoginProvider, string Name) key,
		string value, string stored, CancellationToken cancellationToken = default)
	{
		var dialect = DialectOf(context);
		var tokens = dialect.Tokens;
		using Binder bind = new(context, context.UserTokens.EntityType);
		var column = tokens.Columns[nameof(NorseUserToken.Value)];
		var sql = $"""
			UPDATE {tokens.Name}
			SET {column} = {bind.Value(nameof(NorseUserToken.Value), value)}
			WHERE {TokenKey(tokens, bind, key)} AND {column}{dialect.BinaryCollation} = {bind.Stored(nameof(NorseUserToken.Value), stored)}
			""";
		return context.Database.ExecuteSqlRawAsync(sql, bind.Parameters, cancellationToken);
	}

	/// <summary>
	///     The add-claim statement (spec §4.6): insert-if-absent against the unique key
	///     <c>(user_id, claim_type, claim_value_hash)</c>, so an identical claim is never stored twice. The hash column
	///     is generated and is never named in the write (PoC G6: an explicit value is refused).
	/// </summary>
	/// <param name="context">The context, inside the flush's transaction.</param>
	/// <param name="userId">The user.</param>
	/// <param name="type">The claim type.</param>
	/// <param name="value">The claim value.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>The number of rows inserted: 1, or 0 when the claim was already present.</returns>
	public static Task<int> InsertClaimIfAbsentAsync(NorseIdentityDbContext context, Guid userId, string type, string value,
		CancellationToken cancellationToken = default)
	{
		var dialect = DialectOf(context);
		var claims = dialect.Claims;
		using Binder bind = new(context, context.UserClaims.EntityType);
		string
			userColumn = claims.Columns[nameof(NorseUserClaim.UserId)],
			typeColumn = claims.Columns[nameof(NorseUserClaim.ClaimType)],
			valueColumn = claims.Columns[nameof(NorseUserClaim.ClaimValue)],
			hashColumn = claims.Columns[NorseUserClaim.ClaimValueHash],
			user = bind.Value(nameof(NorseUserClaim.UserId), userId),
			claimType = bind.Value(nameof(NorseUserClaim.ClaimType), type),
			claimValue = bind.Value(nameof(NorseUserClaim.ClaimValue), value);
		var sql = dialect.Merges ?
			$"""
			MERGE {claims.Name} WITH (HOLDLOCK) AS t
			USING (VALUES ({user}, {claimType}, CAST({claimValue} AS nvarchar(max)))) AS s ({userColumn}, {typeColumn}, {valueColumn})
			ON t.{userColumn} = s.{userColumn} AND t.{typeColumn} = s.{typeColumn} AND t.{hashColumn} = {Format(dialect.ClaimHash, $"s.{valueColumn}")}
			WHEN NOT MATCHED THEN INSERT ({userColumn}, {typeColumn}, {valueColumn}) VALUES (s.{userColumn}, s.{typeColumn}, s.{valueColumn});
			""" :
			$"""
			INSERT INTO {claims.Name} ({userColumn}, {typeColumn}, {valueColumn}) VALUES ({user}, {claimType}, {claimValue})
			ON CONFLICT ({userColumn}, {typeColumn}, {hashColumn}) DO NOTHING
			""";
		return context.Database.ExecuteSqlRawAsync(sql, bind.Parameters, cancellationToken);
	}

	/// <summary>
	///     The replace-claim statement (spec §4.6): rewrites the claim matching the old type and the hash of the old
	///     value, unless the user already holds the new claim. Claims are a set, so that case is
	///     <see cref="DeleteReplacedClaimAsync" />'s, and rewriting would collide with the unique key.
	/// </summary>
	/// <param name="context">The context, inside the flush's transaction.</param>
	/// <param name="userId">The user.</param>
	/// <param name="claim">The old claim's type and value.</param>
	/// <param name="replacement">The new claim's type and value.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>The number of rows rewritten.</returns>
	public static Task<int> ReplaceClaimAsync(NorseIdentityDbContext context, Guid userId, (string Type, string Value) claim,
		(string Type, string Value) replacement, CancellationToken cancellationToken = default)
	{
		var dialect = DialectOf(context);
		var claims = dialect.Claims;
		using Binder bind = new(context, context.UserClaims.EntityType);
		var set =
			$"{claims.Columns[nameof(NorseUserClaim.ClaimType)]} = {bind.Value(nameof(NorseUserClaim.ClaimType), replacement.Type)}, {claims.Columns[nameof(NorseUserClaim.ClaimValue)]} = {bind.Value(nameof(NorseUserClaim.ClaimValue), replacement.Value)}";
		var sql = $"""
			UPDATE {claims.Name}
			SET {set}
			WHERE {ClaimKey(dialect, bind, userId, claim)}
			AND NOT EXISTS ({HeldElsewhere(dialect, bind, userId, replacement)})
			""";
		return context.Database.ExecuteSqlRawAsync(sql, bind.Parameters, cancellationToken);
	}

	/// <summary>
	///     The converging half of a replace (ruled 2026-10-25): when the user already holds the new claim, the old one
	///     is deleted by its key, so the set ends as exactly the new claim.
	/// </summary>
	/// <param name="context">The context, inside the flush's transaction.</param>
	/// <param name="userId">The user.</param>
	/// <param name="claim">The old claim's type and value.</param>
	/// <param name="replacement">The new claim's type and value.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>The number of rows deleted.</returns>
	public static Task<int> DeleteReplacedClaimAsync(NorseIdentityDbContext context, Guid userId, (string Type, string Value) claim,
		(string Type, string Value) replacement, CancellationToken cancellationToken = default)
	{
		var dialect = DialectOf(context);
		var claims = dialect.Claims;
		using Binder bind = new(context, context.UserClaims.EntityType);
		var sql = $"""
			DELETE FROM {claims.Name}
			WHERE {ClaimKey(dialect, bind, userId, claim)}
			AND EXISTS ({HeldElsewhere(dialect, bind, userId, replacement)})
			""";
		return context.Database.ExecuteSqlRawAsync(sql, bind.Parameters, cancellationToken);
	}

	/// <summary>Whether the user holds <paramref name="claim" />, matched by type and value hash.</summary>
	/// <param name="context">The context, inside the flush's transaction.</param>
	/// <param name="userId">The user.</param>
	/// <param name="claim">The claim's type and value.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	public static async Task<bool> ClaimExistsAsync(NorseIdentityDbContext context, Guid userId, (string Type, string Value) claim,
		CancellationToken cancellationToken = default)
	{
		var dialect = DialectOf(context);
		using Binder bind = new(context, context.UserClaims.EntityType);
		var sql = $"""
			SELECT COUNT(*) AS {dialect.ValueAlias}
			FROM {dialect.Claims.Name}
			WHERE {ClaimKey(dialect, bind, userId, claim)}
			""";
		var counts = await context.Database
			.SqlQueryRaw<int>(sql, [.. bind.Parameters])
			.ToListAsync(cancellationToken)
			.ConfigureAwait(false);
		return counts is [> 0];
	}

	/// <summary>The remove-claim statement (spec §4.6): a delete by type and value hash.</summary>
	/// <param name="context">The context, inside the flush's transaction.</param>
	/// <param name="userId">The user.</param>
	/// <param name="claim">The claim's type and value.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>The number of rows deleted.</returns>
	public static Task<int> DeleteClaimAsync(NorseIdentityDbContext context, Guid userId, (string Type, string Value) claim,
		CancellationToken cancellationToken = default)
	{
		var dialect = DialectOf(context);
		using Binder bind = new(context, context.UserClaims.EntityType);
		var sql = $"""
			DELETE FROM {dialect.Claims.Name}
			WHERE {ClaimKey(dialect, bind, userId, claim)}
			""";
		return context.Database.ExecuteSqlRawAsync(sql, bind.Parameters, cancellationToken);
	}

	/// <summary>The add-role statement (spec §4.6): insert-if-absent on the primary key <c>(user_id, role_id)</c>.</summary>
	/// <param name="context">The context, inside the flush's transaction.</param>
	/// <param name="userId">The user.</param>
	/// <param name="roleId">The role.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>The number of rows inserted: 1, or 0 when the user already held the role.</returns>
	public static Task<int> InsertRoleIfAbsentAsync(NorseIdentityDbContext context, Guid userId, Guid roleId,
		CancellationToken cancellationToken = default)
	{
		var dialect = DialectOf(context);
		var roles = dialect.Roles;
		using Binder bind = new(context, context.UserRoles.EntityType);
		string
			userColumn = roles.Columns[nameof(NorseUserRole.UserId)],
			roleColumn = roles.Columns[nameof(NorseUserRole.RoleId)],
			user = bind.Value(nameof(NorseUserRole.UserId), userId),
			role = bind.Value(nameof(NorseUserRole.RoleId), roleId);
		var sql = dialect.Merges ?
			$"""
			MERGE {roles.Name} WITH (HOLDLOCK) AS t
			USING (VALUES ({user}, {role})) AS s ({userColumn}, {roleColumn})
			ON t.{userColumn} = s.{userColumn} AND t.{roleColumn} = s.{roleColumn}
			WHEN NOT MATCHED THEN INSERT ({userColumn}, {roleColumn}) VALUES (s.{userColumn}, s.{roleColumn});
			""" :
			$"""
			INSERT INTO {roles.Name} ({userColumn}, {roleColumn}) VALUES ({user}, {role})
			ON CONFLICT ({userColumn}, {roleColumn}) DO NOTHING
			""";
		return context.Database.ExecuteSqlRawAsync(sql, bind.Parameters, cancellationToken);
	}

	/// <summary>
	///     The add-login statement (spec §4.6): a plain <c>INSERT</c> on the primary key
	///     <c>(login_provider, provider_key)</c>. A conflict throws, and on PostgreSQL aborts the transaction (PoC G4);
	///     the caller decides what it meant.
	/// </summary>
	/// <param name="context">The context, inside the flush's transaction.</param>
	/// <param name="userId">The user.</param>
	/// <param name="login">The login.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	public static Task<int> InsertLoginAsync(NorseIdentityDbContext context, Guid userId, StagedIntent.AddLogin login,
		CancellationToken cancellationToken = default)
	{
		var logins = DialectOf(context).Logins;
		using Binder bind = new(context, context.UserLogins.EntityType);
		string[] columns =
		[
			nameof(NorseUserLogin.LoginProvider), nameof(NorseUserLogin.ProviderKey), nameof(NorseUserLogin.ProviderDisplayName),
			nameof(NorseUserLogin.UserId)
		];
		object?[] values = [login.LoginProvider, login.ProviderKey, login.ProviderDisplayName, userId];
		var sql = $"""
			INSERT INTO {logins.Name} ({string.Join(", ", columns.Select(column => logins.Columns[column]))})
			VALUES ({string.Join(", ", columns.Zip(values, bind.Value))})
			""";
		return context.Database.ExecuteSqlRawAsync(sql, bind.Parameters, cancellationToken);
	}

	/// <summary>
	///     The token upsert (spec §4.6, PoC G4): PostgreSQL <c>INSERT … ON CONFLICT … DO UPDATE</c>, SQL Server
	///     <c>MERGE … WITH (HOLDLOCK)</c>, on <c>(user_id, login_provider, name)</c>. The value goes through the model's
	///     converter, so it is encrypted under the caller's crypto scope.
	/// </summary>
	/// <param name="context">The context, inside the flush's transaction.</param>
	/// <param name="key">The token's key.</param>
	/// <param name="value">The plaintext value.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	public static Task<int> UpsertTokenAsync(NorseIdentityDbContext context, (Guid UserId, string LoginProvider, string Name) key,
		string? value, CancellationToken cancellationToken = default)
	{
		var dialect = DialectOf(context);
		var tokens = dialect.Tokens;
		using Binder bind = new(context, context.UserTokens.EntityType);
		string
			userColumn = tokens.Columns[nameof(NorseUserToken.UserId)],
			providerColumn = tokens.Columns[nameof(NorseUserToken.LoginProvider)],
			nameColumn = tokens.Columns[nameof(NorseUserToken.Name)],
			valueColumn = tokens.Columns[nameof(NorseUserToken.Value)],
			user = bind.Value(nameof(NorseUserToken.UserId), key.UserId),
			provider = bind.Value(nameof(NorseUserToken.LoginProvider), key.LoginProvider),
			name = bind.Value(nameof(NorseUserToken.Name), key.Name),
			stored = bind.Value(nameof(NorseUserToken.Value), value);
		var sql = dialect.Merges ?
			$"""
			MERGE {tokens.Name} WITH (HOLDLOCK) AS t
			USING (VALUES ({user}, {provider}, {name}, {stored})) AS s ({userColumn}, {providerColumn}, {nameColumn}, {valueColumn})
			ON t.{userColumn} = s.{userColumn} AND t.{providerColumn} = s.{providerColumn} AND t.{nameColumn} = s.{nameColumn}
			WHEN MATCHED THEN UPDATE SET {valueColumn} = s.{valueColumn}
			WHEN NOT MATCHED THEN INSERT ({userColumn}, {providerColumn}, {nameColumn}, {valueColumn}) VALUES (s.{userColumn}, s.{providerColumn}, s.{nameColumn}, s.{valueColumn});
			""" :
			$"""
			INSERT INTO {tokens.Name} ({userColumn}, {providerColumn}, {nameColumn}, {valueColumn}) VALUES ({user}, {provider}, {name}, {stored})
			ON CONFLICT ({userColumn}, {providerColumn}, {nameColumn}) DO UPDATE SET {valueColumn} = EXCLUDED.{valueColumn}
			""";
		return context.Database.ExecuteSqlRawAsync(sql, bind.Parameters, cancellationToken);
	}

	/// <summary>
	///     The passkey assertion update (spec §4.6): rewrites the document's name, sign count and flags where the row
	///     still belongs to the user and still holds the as-read sign count -- never an insert. A newer count or a
	///     removed credential matches nothing.
	/// </summary>
	/// <param name="context">The context, inside the flush's transaction.</param>
	/// <param name="userId">The user.</param>
	/// <param name="update">The credential, its as-read sign count, and the new values.</param>
	/// <param name="cancellationToken">The cancellation token.</param>
	/// <returns>The number of rows matched: 1, or 0 when the guard failed.</returns>
	public static Task<int> UpdatePasskeyAsync(NorseIdentityDbContext context, Guid userId, StagedIntent.UpdatePasskey update,
		CancellationToken cancellationToken = default)
	{
		var dialect = DialectOf(context);
		var passkeys = dialect.Passkeys;
		using Binder bind = new(context, context.UserPasskeys.EntityType);
		var data = passkeys.Columns[nameof(NorseUserPasskey.Data)];
		var document = string.Format(CultureInfo.InvariantCulture, dialect.PasskeyAssertion, data, bind.Typed(update.Name),
			bind.Typed((long)update.SignCount), bind.Typed(update.IsUserVerified), bind.Typed(update.IsBackedUp));
		var where = string.Join(" AND ", [
			$"{passkeys.Columns[nameof(NorseUserPasskey.CredentialId)]} = {bind.Value(nameof(NorseUserPasskey.CredentialId), update.CredentialId)}",
			$"{passkeys.Columns[nameof(NorseUserPasskey.UserId)]} = {bind.Value(nameof(NorseUserPasskey.UserId), userId)}",
			$"{Format(dialect.PasskeySignCount, data)} = {bind.Typed((long)update.BaselineSignCount)}"
		]);
		var sql = $"""
			UPDATE {passkeys.Name}
			SET {data} = {document}
			WHERE {where}
			""";
		return context.Database.ExecuteSqlRawAsync(sql, bind.Parameters, cancellationToken);
	}

	static string ClaimKey(Dialect dialect, Binder bind, Guid userId, (string Type, string Value) claim, string qualifier = "") =>
		string.Join(" AND ", [
			$"{qualifier}{dialect.Claims.Columns[nameof(NorseUserClaim.UserId)]} = {bind.Value(nameof(NorseUserClaim.UserId), userId)}",
			$"{qualifier}{dialect.Claims.Columns[nameof(NorseUserClaim.ClaimType)]} = {bind.Value(nameof(NorseUserClaim.ClaimType), claim.Type)}",
			$"{qualifier}{dialect.Claims.Columns[NorseUserClaim.ClaimValueHash]} = {Format(dialect.ClaimHash, bind.Value(nameof(NorseUserClaim.ClaimValue), claim.Value))}"
		]);

	/// <summary>
	///     A row other than the one being replaced that holds <paramref name="replacement" />. The old claim's own row
	///     must never count: wherever both keys match it (an identical claim, or a type differing only in case under a
	///     case-insensitive collation), counting it would skip the rewrite and converge the claim away (PR #76 review).
	/// </summary>
	static string HeldElsewhere(Dialect dialect, Binder bind, Guid userId, (string Type, string Value) replacement)
	{
		var id = dialect.Claims.Columns[nameof(NorseUserClaim.Id)];
		return $"SELECT 1 FROM {dialect.Claims.Name} AS held WHERE {ClaimKey(dialect, bind, userId, replacement, "held.")} AND held.{id} <> {dialect.Claims.Name}.{id}";
	}

	static string Format(string format, string operand) =>
		string.Format(CultureInfo.InvariantCulture, format, operand);

	static string TokenKey(Table tokens, Binder bind, (Guid UserId, string LoginProvider, string Name) key) =>
		string.Join(" AND ", [
			$"{tokens.Columns[nameof(NorseUserToken.UserId)]} = {bind.Value(nameof(NorseUserToken.UserId), key.UserId)}",
			$"{tokens.Columns[nameof(NorseUserToken.LoginProvider)]} = {bind.Value(nameof(NorseUserToken.LoginProvider), key.LoginProvider)}",
			$"{tokens.Columns[nameof(NorseUserToken.Name)]} = {bind.Value(nameof(NorseUserToken.Name), key.Name)}"
		]);

	static Dialect DialectOf(NorseIdentityDbContext context) =>
		context.Database.ProviderName == NorseDbContextOptionsExtensions.SqlServerProviderName ?
			_sqlServer :
			_postgreSql;

	/// <summary>
	///     Builds one statement's parameters from the model's own type mapping for each property, naming them
	///     <c>p0</c>, <c>p1</c>, … in binding order.
	/// </summary>
	/// <param name="context">The context whose connection makes the parameters.</param>
	/// <param name="entity">The entity whose properties the values belong to.</param>
	sealed class Binder(NorseIdentityDbContext context, IEntityType entity) : IDisposable
	{
		readonly DbCommand _factory = context.Database.GetDbConnection().CreateCommand();
		readonly List<DbParameter> _parameters = [];

		/// <summary>The entity whose properties are bound.</summary>
		public IEntityType Entity => entity;

		/// <summary>The parameters bound so far.</summary>
		public IReadOnlyList<DbParameter> Parameters => _parameters;

		/// <summary>Binds a model value: the property's converter applies, as EF would apply it.</summary>
		public string Value(string property, object? value)
		{
			var mapped = entity.GetProperty(property);
			return Add(mapped.GetRelationalTypeMapping(), mapped, value);
		}

		/// <summary>
		///     Binds a value exactly as stored: the column's store type, without the property's converter.
		/// </summary>
		public string Stored(string property, object? stored)
		{
			var mapped = entity.GetProperty(property);
			var storeType = mapped.GetColumnType();
			var mapping = context.GetService<IRelationalTypeMappingSource>().FindMapping(typeof(string), storeType) ??
				throw new InvalidOperationException($"No string mapping for store type {storeType}.");
			return Add(mapping, mapped, stored);
		}

		/// <summary>
		///     Binds a value that belongs to no mapped column (a property inside a JSON document) with the provider's
		///     default mapping for its CLR type, so it is typed even when <see langword="null" />.
		/// </summary>
		public string Typed<T>(T value)
		{
			var mapping = context.GetService<IRelationalTypeMappingSource>().FindMapping(typeof(T)) ??
				throw new InvalidOperationException($"No default mapping for {typeof(T).Name}.");
			var name = $"p{_parameters.Count}";
			_parameters.Add(mapping.CreateParameter(_factory, name, value, nullable: value is null));
			return $"@{name}";
		}

		/// <inheritdoc />
		public void Dispose() =>
			_factory.Dispose();

		string Add(RelationalTypeMapping mapping, IProperty mapped, object? value)
		{
			var name = $"p{_parameters.Count}";
			_parameters.Add(mapping.CreateParameter(_factory, name, value, mapped.IsNullable));
			return $"@{name}";
		}
	}

	/// <summary>One provider's spelling of a table: its delimited name and its delimited columns.</summary>
	/// <param name="Name">The delimited table name.</param>
	/// <param name="Columns">The delimited column name of each mapped property, by property name.</param>
	sealed record Table(string Name, IReadOnlyDictionary<string, string> Columns);

	/// <summary>One provider's spelling of the tables the store writes raw, and of a value returned from a write.</summary>
	/// <param name="Credentials">The <c>user_credentials</c> fragment, by <see cref="NorseUser" /> property name.</param>
	/// <param name="Tokens">The <c>user_tokens</c> table, by <see cref="NorseUserToken" /> property name.</param>
	/// <param name="ValueAlias">The delimited <c>Value</c> alias a scalar <c>SqlQuery</c> reads.</param>
	/// <param name="Returning">The trailing returning clause, a format over the returned column (PostgreSQL).</param>
	/// <param name="Output">The returning clause between <c>SET</c> and <c>WHERE</c>, likewise (SQL Server).</param>
	/// <param name="BinaryCollation">The suffix that makes a text comparison byte-exact, if the default isn't.</param>
	/// <param name="Claims">The <c>user_claims</c> table, by <see cref="NorseUserClaim" /> property name.</param>
	/// <param name="Logins">The <c>user_logins</c> table, by <see cref="NorseUserLogin" /> property name.</param>
	/// <param name="Roles">The <c>user_roles</c> table, by <see cref="NorseUserRole" /> property name.</param>
	/// <param name="Passkeys">The <c>user_passkeys</c> table, by <see cref="NorseUserPasskey" /> property name.</param>
	/// <param name="ClaimHash">A format over a claim-value expression that hashes it as the stored column does.</param>
	/// <param name="PasskeySignCount">A format over the passkey document reading its sign count as a <c>bigint</c>.</param>
	/// <param name="PasskeyAssertion">
	///     A format over the passkey document and the new name, sign count, user-verified and backed-up values that
	///     rewrites those four properties and leaves every other one (the public key, the attestation) as stored.
	/// </param>
	/// <param name="Merges">
	///     Whether the provider's insert-if-absent and upsert are <c>MERGE … WITH (HOLDLOCK)</c> (SQL Server) rather
	///     than <c>INSERT … ON CONFLICT</c> (PostgreSQL). PoC G4: both hold under concurrent writers; the naive forms
	///     do not.
	/// </param>
	/// <param name="LockHint">
	///     The table hint after a table name that takes an update lock held to the end of the transaction (SQL Server).
	/// </param>
	/// <param name="LockSuffix">The trailing clause that does the same for a whole <c>SELECT</c> (PostgreSQL).</param>
	sealed record Dialect(Table Credentials, Table Tokens, Table Claims, Table Logins, Table Roles,
		Table Passkeys, string ValueAlias, string Returning, string Output, string BinaryCollation, string ClaimHash,
		string PasskeySignCount, string PasskeyAssertion, bool Merges, string LockHint, string LockSuffix);
}
