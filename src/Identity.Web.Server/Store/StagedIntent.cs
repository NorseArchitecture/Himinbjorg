using Microsoft.AspNetCore.Identity;

namespace Norse.Identity.Web.Server.Store;

/// <summary>
///     A typed write intent a mutating store method stages against an instance (2026-10-24 explicit-writes spec §4.3),
///     for a change the plaintext diff (§4.2) cannot express. Nothing touches the database until
///     <see cref="NorseUserStore.UpdateAsync" /> flushes, and a failed or abandoned operation drops every intent.
/// </summary>
/// <remarks>
///     A closed hierarchy: the constructor is private, so every intent is one of the nested records below. Every
///     child-row intent (§4.6) is one statement in the flush's transaction, in staging order.
/// </remarks>
abstract record StagedIntent
{
	StagedIntent()
	{
	}

	/// <summary>
	///     <c>access_failed_count = 0</c>, unconditionally (spec §4.4). The diff alone can't carry it: a concurrent
	///     increment may have raised the stored count while the instance still reads 0, and a reset follows either a
	///     proven password or a lockout, so clobbering that increment is correct in both cases.
	/// </summary>
	internal sealed record ResetAccessFailedCount : StagedIntent
	{
		ResetAccessFailedCount()
		{
		}

		/// <summary>The one instance: the intent carries no data.</summary>
		public static ResetAccessFailedCount Instance { get; } = new();
	}

	/// <summary>Insert-if-absent on <c>(user_id, claim_type, claim_value_hash)</c>: claims are a set (spec §4.6).</summary>
	/// <param name="Type">The claim type.</param>
	/// <param name="Value">The claim value.</param>
	internal sealed record AddClaim(string Type, string Value) : StagedIntent;

	/// <summary>
	///     Rewrites every claim matching <paramref name="Type" /> and the hash of <paramref name="Value" />. Zero rows
	///     with the new claim already present is a replay, so success; zero rows otherwise is a concurrency failure.
	/// </summary>
	/// <param name="Type">The old claim type.</param>
	/// <param name="Value">The old claim value.</param>
	/// <param name="NewType">The new claim type.</param>
	/// <param name="NewValue">The new claim value.</param>
	internal sealed record ReplaceClaim(string Type, string Value, string NewType, string NewValue) : StagedIntent;

	/// <summary>Deletes the claim by its key: type and value hash.</summary>
	/// <param name="Type">The claim type.</param>
	/// <param name="Value">The claim value.</param>
	internal sealed record RemoveClaim(string Type, string Value) : StagedIntent;

	/// <summary>
	///     Inserts on the primary key <c>(login_provider, provider_key)</c>. A conflict with the same user's row is a
	///     replay, so success; one with another user's row fails the flush.
	/// </summary>
	/// <param name="LoginProvider">The external provider.</param>
	/// <param name="ProviderKey">The user's key at that provider.</param>
	/// <param name="ProviderDisplayName">The provider's display name.</param>
	internal sealed record AddLogin(string LoginProvider, string ProviderKey, string? ProviderDisplayName) : StagedIntent;

	/// <summary>Deletes the login by its key.</summary>
	/// <param name="LoginProvider">The external provider.</param>
	/// <param name="ProviderKey">The user's key at that provider.</param>
	internal sealed record RemoveLogin(string LoginProvider, string ProviderKey) : StagedIntent;

	/// <summary>Insert-if-absent on the primary key <c>(user_id, role_id)</c>.</summary>
	/// <param name="RoleId">The role, resolved from its normalized name when staged.</param>
	internal sealed record AddRole(Guid RoleId) : StagedIntent;

	/// <summary>Deletes the membership by its key.</summary>
	/// <param name="RoleId">The role, resolved from its normalized name when staged.</param>
	internal sealed record RemoveRole(Guid RoleId) : StagedIntent;

	/// <summary>
	///     The provider-native upsert on <c>(user_id, login_provider, name)</c>: concurrent creators of one key both
	///     succeed, and the last committed value wins. Serves the authenticator key and the recovery-code set too.
	/// </summary>
	/// <param name="LoginProvider">The token's provider.</param>
	/// <param name="Name">The token's name.</param>
	/// <param name="Value">The plaintext value, encrypted by the model's converter when the flush binds it.</param>
	internal sealed record UpsertToken(string LoginProvider, string Name, string? Value) : StagedIntent;

	/// <summary>
	///     Insert-if-absent on <c>(user_id, login_provider, name)</c>: writes the value only where no value is stored,
	///     so of two concurrent creators the first committed wins and the second writes nothing. The authenticator key's
	///     first provisioning (Train 3 Task 4.4): the caller re-reads, and every racer answers the one key stored.
	/// </summary>
	/// <param name="LoginProvider">The token's provider.</param>
	/// <param name="Name">The token's name.</param>
	/// <param name="Value">The plaintext value, encrypted by the model's converter when the flush binds it.</param>
	internal sealed record InsertTokenIfAbsent(string LoginProvider, string Name, string Value) : StagedIntent;

	/// <summary>Deletes the token by its key.</summary>
	/// <param name="LoginProvider">The token's provider.</param>
	/// <param name="Name">The token's name.</param>
	internal sealed record RemoveToken(string LoginProvider, string Name) : StagedIntent;

	/// <summary>
	///     A passkey enrollment: an <c>INSERT</c>, never an upsert. A conflict on the credential id with an identical
	///     row (same user, same public key) is a replay, so success; any other conflict fails the flush.
	/// </summary>
	/// <param name="CredentialId">The credential id.</param>
	/// <param name="Data">The passkey document, as enrolled.</param>
	internal sealed record EnrollPasskey(byte[] CredentialId, IdentityPasskeyData Data) : StagedIntent;

	/// <summary>
	///     A passkey assertion update (sign count, flags, rename): an <c>UPDATE</c> guarded by the sign count the
	///     store returned for this instance, never an insert. Zero rows -- a newer count, or a removed credential --
	///     fails the flush, so sign-in fails closed.
	/// </summary>
	/// <param name="CredentialId">The credential id.</param>
	/// <param name="BaselineSignCount">The sign count as read through the store.</param>
	/// <param name="Name">The passkey's new name.</param>
	/// <param name="SignCount">The new sign count.</param>
	/// <param name="IsUserVerified">The new user-verified flag.</param>
	/// <param name="IsBackedUp">The new backed-up flag.</param>
	internal sealed record UpdatePasskey(byte[] CredentialId, uint BaselineSignCount, string? Name, uint SignCount, bool IsUserVerified,
		bool IsBackedUp) : StagedIntent;

	/// <summary>Deletes the passkey by its credential id.</summary>
	/// <param name="CredentialId">The credential id.</param>
	internal sealed record RemovePasskey(byte[] CredentialId) : StagedIntent;
}
