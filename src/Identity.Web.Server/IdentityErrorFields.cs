using Norse.AuthN.Services;

namespace Norse.Identity.Web.Server;

/// <summary>
///     Regroups an Identity failure's errors by the <em>wire field</em> each belongs on. The <c>.Outcome</c> view keys
///     errors by <c>IdentityError.Code</c>, but the client's <c>ServerErrorCoordinator</c> builds a
///     <c>FieldIdentifier</c> from the dictionary's keys, and a key like <c>PasswordRequiresNonAlphanumeric</c> matches
///     no bound field, so the message renders nowhere (neither inline nor in the model-level summary, which only fires
///     when the errors are empty) -- silently dropped, reproduced live 2026-08-07.
/// </summary>
static class IdentityErrorFields
{
	/// <summary>Regroups <paramref name="errors" /> by <see cref="For" />, concatenating each field's messages.</summary>
	/// <param name="errors">The view's errors, keyed by <c>IdentityError.Code</c>.</param>
	/// <returns>The same messages, keyed by wire field.</returns>
	public static Dictionary<string, string[]> Regroup(IReadOnlyDictionary<string, string[]> errors) =>
		Regroup(errors, For);

	/// <summary>Regroups <paramref name="errors" /> by <paramref name="fieldFor" />, concatenating each field's messages.</summary>
	/// <param name="errors">The view's errors, keyed by <c>IdentityError.Code</c>.</param>
	/// <param name="fieldFor">Maps an Identity error code onto its wire field, or the empty model-level key.</param>
	/// <returns>The same messages, keyed by wire field.</returns>
	public static Dictionary<string, string[]> Regroup(IReadOnlyDictionary<string, string[]> errors,
		Func<string, string> fieldFor) =>
		errors
			.GroupBy(error => fieldFor(error.Key))
			.ToDictionary(static group => group.Key, string[] (group) => [.. group.SelectMany(static error => error.Value)]);

	/// <summary>
	///     The wire field an Identity error code belongs on. Every request that surfaces these codes names its fields
	///     <c>Email</c> and <c>Password</c>, and the platform sets <c>UserName</c> to <c>Email</c>, so every
	///     user-name-shaped code belongs on the email field too. Every code a role-free create or reset actually emits
	///     is named explicitly rather than pattern-matched, so a future code this platform has never seen fails safe
	///     to the model-level summary (the empty key) instead of silently mapping to the wrong field.
	/// </summary>
	/// <param name="identityErrorCode">The <c>IdentityError.Code</c>.</param>
	/// <returns>The wire field's name, or the empty model-level key.</returns>
	public static string For(string identityErrorCode) => identityErrorCode switch
	{
		"DuplicateUserName" or "DuplicateEmail" or "InvalidUserName" or "InvalidEmail" => nameof(RegisterRequest.Email),
		"PasswordTooShort" or "PasswordRequiresUniqueChars" or "PasswordRequiresNonAlphanumeric" or
			"PasswordRequiresDigit" or "PasswordRequiresLower"
			or "PasswordRequiresUpper" => nameof(RegisterRequest.Password),
		_ => ""
	};

	/// <summary>
	///     The wire field an Identity error code belongs on for a password change, whose request names its fields
	///     <c>OldPassword</c> and <c>NewPassword</c>: a mismatch is the current password's fault, every password rule
	///     the new one's. Anything else fails safe to the model-level summary, as in <see cref="For" />.
	/// </summary>
	/// <param name="identityErrorCode">The <c>IdentityError.Code</c>.</param>
	/// <returns>The wire field's name, or the empty model-level key.</returns>
	public static string ForPasswordChange(string identityErrorCode) => identityErrorCode switch
	{
		"PasswordMismatch" => nameof(ChangePasswordRequest.OldPassword),
		"PasswordTooShort" or "PasswordRequiresUniqueChars" or "PasswordRequiresNonAlphanumeric" or
			"PasswordRequiresDigit" or "PasswordRequiresLower"
			or "PasswordRequiresUpper" => nameof(ChangePasswordRequest.NewPassword),
		_ => ""
	};
}
