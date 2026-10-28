using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using OpenIddict.Abstractions;

namespace Norse.Identity.Outcomes;

/// <summary>
///     The mapping law (2026-10-24 explicit-writes spec §4.12): the one table that turns an Identity or OpenIddict
///     answer into an <see cref="Outcome{T}" />. No other code translates <see cref="IdentityResult" />,
///     <see cref="SignInResult" /> or an OpenIddict exception; the <c>.Outcome</c> views call this.
/// </summary>
/// <remarks>
///     Every <see cref="IdentityErrorDescriber" /> code on the pinned Identity version and every
///     <see cref="NorseIdentityErrorCodes" /> constant has an explicit row, pinned by a test that enumerates both, so a
///     new code fails the build instead of falling through. A code with no row still answers
///     <see cref="ErrorCategory.Fault" />, never a silent default.
/// </remarks>
public static class IdentityOutcomeMap
{
	/// <summary>The table: spec §4.12, with the rows ruled 2026-10-25.</summary>
	static readonly FrozenDictionary<string, ErrorCategory> _codes = new Dictionary<string, ErrorCategory>(StringComparer.Ordinal)
	{
		// The thing already exists, belongs to someone else, or moved underneath the caller.
		[nameof(IdentityErrorDescriber.ConcurrencyFailure)] = ErrorCategory.Conflict,
		[nameof(IdentityErrorDescriber.DuplicateEmail)] = ErrorCategory.Conflict,
		[nameof(IdentityErrorDescriber.DuplicateUserName)] = ErrorCategory.Conflict,
		[nameof(IdentityErrorDescriber.LoginAlreadyAssociated)] = ErrorCategory.Conflict,
		[nameof(IdentityErrorDescriber.UserAlreadyHasPassword)] = ErrorCategory.Conflict,
		[nameof(IdentityErrorDescriber.UserAlreadyInRole)] = ErrorCategory.Conflict,
		[nameof(IdentityErrorDescriber.DuplicateRoleName)] = ErrorCategory.Conflict,
		[NorseIdentityErrorCodes.PasskeyAlreadyRegistered] = ErrorCategory.Conflict,
		[NorseIdentityErrorCodes.LastSignInMethod] = ErrorCategory.Conflict,
		// Password, username, email and role-name validators, and the refused username set (spec §3.1).
		[nameof(IdentityErrorDescriber.InvalidEmail)] = ErrorCategory.Validation,
		[nameof(IdentityErrorDescriber.InvalidUserName)] = ErrorCategory.Validation,
		[nameof(IdentityErrorDescriber.InvalidRoleName)] = ErrorCategory.Validation,
		[nameof(IdentityErrorDescriber.PasswordTooShort)] = ErrorCategory.Validation,
		[nameof(IdentityErrorDescriber.PasswordRequiresDigit)] = ErrorCategory.Validation,
		[nameof(IdentityErrorDescriber.PasswordRequiresLower)] = ErrorCategory.Validation,
		[nameof(IdentityErrorDescriber.PasswordRequiresUpper)] = ErrorCategory.Validation,
		[nameof(IdentityErrorDescriber.PasswordRequiresNonAlphanumeric)] = ErrorCategory.Validation,
		[nameof(IdentityErrorDescriber.PasswordRequiresUniqueChars)] = ErrorCategory.Validation,
		[NorseIdentityErrorCodes.UserNameIsDerived] = ErrorCategory.Validation,
		// A submitted proof failed.
		[nameof(IdentityErrorDescriber.PasswordMismatch)] = ErrorCategory.InvalidCredentials,
		[nameof(IdentityErrorDescriber.InvalidToken)] = ErrorCategory.InvalidCredentials,
		[nameof(IdentityErrorDescriber.RecoveryCodeRedemptionFailed)] = ErrorCategory.InvalidCredentials,
		[nameof(IdentityErrorDescriber.UserNotInRole)] = ErrorCategory.NotFound,
		// A programming or configuration error: the platform enables lockout for every user.
		[nameof(IdentityErrorDescriber.UserLockoutNotEnabled)] = ErrorCategory.Fault,
		[nameof(IdentityErrorDescriber.DefaultError)] = ErrorCategory.Fault,
		// A provisioning write that left no key stored: the store failed its contract.
		[NorseIdentityErrorCodes.AuthenticatorKeyNotStored] = ErrorCategory.Fault,
		// The commit may or may not have landed; re-read before acting (spec §4.10).
		[NorseIdentityErrorCodes.IndeterminateOutcome] = ErrorCategory.Indeterminate
	}.ToFrozenDictionary(StringComparer.Ordinal);

	/// <summary>
	///     Whether <paramref name="exception" /> is a deliberately destroyed subject key
	///     (<see cref="KeyDestroyedException" />): the one classification the <c>Erased</c> row and both
	///     framework-boundary adapters (the security-stamp validator and the revalidating state provider) share.
	/// </summary>
	/// <param name="exception">The exception to classify.</param>
	public static bool IsErased(Exception exception) =>
		exception is KeyDestroyedException;

	/// <summary>
	///     Classifies the exceptions the table has a row for: <see cref="IndeterminateWriteException" /> as
	///     <see cref="ErrorCategory.Indeterminate" />, <see cref="KeyDestroyedException" /> as
	///     <see cref="ErrorCategory.Erased" /> with its receipt, OpenIddict's concurrency failure as
	///     <see cref="ErrorCategory.Conflict" />, its other failures and a store's refused methods
	///     (<see cref="NotSupportedException" />) as <see cref="ErrorCategory.Fault" />. Anything else is not classified
	///     and must propagate: cancellation and programming errors are not outcomes.
	/// </summary>
	/// <param name="exception">The exception to classify.</param>
	/// <param name="problem">The failure it answers, when classified.</param>
	/// <returns>Whether the table has a row for <paramref name="exception" />.</returns>
	public static bool TryClassify(Exception exception, [NotNullWhen(true)] out Problem? problem)
	{
		problem = exception switch
		{
			IndeterminateWriteException => new() { Category = ErrorCategory.Indeterminate },
			KeyDestroyedException destroyed => new() { Category = ErrorCategory.Erased, Receipt = destroyed.Receipt },
			OpenIddictExceptions.ConcurrencyException => new() { Category = ErrorCategory.Conflict },
			// OpenIddict's own text (an ID2xxx diagnostic, never personal data) is the only trace the caller gets.
			OpenIddictExceptions.ValidationException or OpenIddictExceptions.ProtocolException =>
				Problem.ModelError(ErrorCategory.Fault, exception.Message),
			NotSupportedException => new() { Category = ErrorCategory.Fault },
			_ => null
		};
		return problem is not null;
	}

	/// <summary>
	///     Maps a sign-in answer: success and a required second factor are successes the caller routes; lockout, a
	///     refused sign-in and failed credentials are failures.
	/// </summary>
	/// <param name="result">The sign-in manager's answer.</param>
	/// <exception cref="ArgumentNullException"><paramref name="result" /> is null.</exception>
	public static Outcome<SignInCompletion> ToOutcome(SignInResult result)
	{
		ArgumentNullException.ThrowIfNull(result);
		return result switch
		{
			{ Succeeded: true } => Outcome<SignInCompletion>.Ok(SignInCompletion.SignedIn),
			{ RequiresTwoFactor: true } => Outcome<SignInCompletion>.Ok(SignInCompletion.RequiresTwoFactor),
			{ IsLockedOut: true } => Outcome<SignInCompletion>.Err(ErrorCategory.LockedOut),
			{ IsNotAllowed: true } => Outcome<SignInCompletion>.Err(ErrorCategory.NotAllowed),
			_ => Outcome<SignInCompletion>.Err(ErrorCategory.InvalidCredentials)
		};
	}

	/// <summary>
	///     Whether <paramref name="code" /> has an explicit row, and its category when it does.
	/// </summary>
	internal static bool TryCategorize(string code, out ErrorCategory category) =>
		_codes.TryGetValue(code, out category);

	/// <summary>
	///     Maps an <see cref="IdentityResult" />: success carries <paramref name="value" />; a failure answers the gravest
	///     category among its errors, with each error's description keyed by its code.
	/// </summary>
	internal static Outcome<T> ToOutcome<T>(IdentityResult result, T value)
		where T : notnull
	{
		ArgumentNullException.ThrowIfNull(result);
		if (result.Succeeded)
			return Outcome<T>.Ok(value);

		var category = result.Errors
			.Select(static error => TryCategorize(error.Code, out var category) ?
				category :
				ErrorCategory.Fault)
			.DefaultIfEmpty(ErrorCategory.Fault)
			.MaxBy(Gravity);
		var errors = result.Errors
			.GroupBy(static error => error.Code, StringComparer.Ordinal)
			.ToDictionary(static group => group.Key, string[] (group) => [.. group.Select(static error => error.Description)]);
		return Outcome<T>.Err(category, errors);
	}

	/// <summary>
	///     Which category a mixed failure answers. A misstated outcome is worst (<c>Indeterminate</c>), then a fault,
	///     then a conflict: a duplicate email beside a weak password answers <c>Conflict</c>, so the caller doesn't
	///     retry a registration that can never succeed.
	/// </summary>
	static int Gravity(ErrorCategory category) => category switch
	{
		ErrorCategory.Indeterminate => 5,
		ErrorCategory.Fault => 4,
		ErrorCategory.Conflict => 3,
		ErrorCategory.NotFound => 2,
		ErrorCategory.InvalidCredentials => 1,
		_ => 0
	};

	/// <summary>
	///     Runs <paramref name="operation" />, answering an exception the table classifies as its failure; anything else
	///     propagates.
	/// </summary>
	internal static async ValueTask<Outcome<T>> GuardAsync<T>(Func<ValueTask<Outcome<T>>> operation)
		where T : notnull
	{
		try
		{
			return await operation().ConfigureAwait(false);
		}
		catch (Exception exception) when (TryClassify(exception, out var problem))
		{
			return new(new Failed(problem));
		}
	}
}
