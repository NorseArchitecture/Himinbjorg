using System.Reflection;
using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Backend.Keys;
using Norse.Abstractions.Contracts;
using Norse.Primitives;
using OpenIddict.Abstractions;

namespace Norse.Identity.Outcomes.Tests;

/// <summary>
///     The one mapping table (2026-10-24 explicit-writes spec §4.12): every <see cref="IdentityErrorDescriber" /> code on
///     the pinned Identity version and every Norse-minted code has an explicit row, and nothing falls through silently.
/// </summary>
public sealed class IdentityOutcomeMapTests
{
	/// <summary>The ruled table (spec §4.12, rows ruled 2026-10-25), restated here so the map can't drift from it.</summary>
	static readonly Dictionary<string, ErrorCategory> _ruled = new(StringComparer.Ordinal)
	{
		[nameof(IdentityErrorDescriber.ConcurrencyFailure)] = ErrorCategory.Conflict,
		[nameof(IdentityErrorDescriber.DuplicateEmail)] = ErrorCategory.Conflict,
		[nameof(IdentityErrorDescriber.DuplicateUserName)] = ErrorCategory.Conflict,
		[nameof(IdentityErrorDescriber.LoginAlreadyAssociated)] = ErrorCategory.Conflict,
		[nameof(IdentityErrorDescriber.UserAlreadyHasPassword)] = ErrorCategory.Conflict,
		[nameof(IdentityErrorDescriber.UserAlreadyInRole)] = ErrorCategory.Conflict,
		[nameof(IdentityErrorDescriber.DuplicateRoleName)] = ErrorCategory.Conflict,
		[NorseIdentityErrorCodes.PasskeyAlreadyRegistered] = ErrorCategory.Conflict,
		[NorseIdentityErrorCodes.LastSignInMethod] = ErrorCategory.Conflict,
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
		[nameof(IdentityErrorDescriber.PasswordMismatch)] = ErrorCategory.InvalidCredentials,
		[nameof(IdentityErrorDescriber.InvalidToken)] = ErrorCategory.InvalidCredentials,
		[nameof(IdentityErrorDescriber.RecoveryCodeRedemptionFailed)] = ErrorCategory.InvalidCredentials,
		[nameof(IdentityErrorDescriber.UserNotInRole)] = ErrorCategory.NotFound,
		[nameof(IdentityErrorDescriber.UserLockoutNotEnabled)] = ErrorCategory.Fault,
		[nameof(IdentityErrorDescriber.DefaultError)] = ErrorCategory.Fault,
		[NorseIdentityErrorCodes.IndeterminateOutcome] = ErrorCategory.Indeterminate
	};

	static readonly ErasureReceipt _receipt = new(Guid.CreateVersion7(), DateTimeOffset.UnixEpoch);

	[Fact]
	void Every_IdentityErrorDescriber_code_has_an_explicit_mapping()
	{
		// Reflection over the pinned describer: invoking each IdentityError factory yields the code it actually
		// answers, so a code added upstream fails here instead of falling through to Fault.
		IdentityErrorDescriber describer = new();
		string[] describerCodes =
		[
			.. typeof(IdentityErrorDescriber)
				.GetMethods(BindingFlags.Public | BindingFlags.Instance)
				.Where(static m => m.ReturnType == typeof(IdentityError))
				.Select(m => ((IdentityError)m.Invoke(describer, [.. m.GetParameters().Select(DummyArgument)])!).Code)
		];
		// And the Norse-minted codes: a new constant needs a row too.
		string[] norseCodes =
		[
			.. typeof(NorseIdentityErrorCodes)
				.GetFields(BindingFlags.Public | BindingFlags.Static)
				.Where(static f => f.IsLiteral)
				.Select(static f => (string)f.GetRawConstantValue()!)
		];
		describerCodes.Length.ShouldBe(22, "the pinned describer (11.0.0-rc.2) answers 22 codes");

		string[] everyCode = [.. describerCodes, .. norseCodes];
		everyCode.ShouldBeUnique();
		everyCode.ShouldBe(_ruled.Keys, ignoreOrder: true);
		foreach (var code in everyCode)
		{
			IdentityOutcomeMap.TryCategorize(code, out var category).ShouldBeTrue($"{code} has no explicit row");
			category.ShouldBe(_ruled[code], code);
		}
	}

	[Fact]
	void Unmapped_code_maps_to_Fault()
	{
		IdentityOutcomeMap.TryCategorize("SomethingUpstreamInventedLater", out _).ShouldBeFalse();

		var outcome = IdentityOutcomeMap.ToOutcome(Failed("SomethingUpstreamInventedLater"), Unit.Value);

		CategoryOf(outcome).ShouldBe(ErrorCategory.Fault);
	}

	[Fact]
	void Last_sign_in_method_maps_to_Conflict()
	{
		IdentityOutcomeMap.TryCategorize(NorseIdentityErrorCodes.LastSignInMethod, out var category).ShouldBeTrue();
		category.ShouldBe(ErrorCategory.Conflict);
	}

	[Fact]
	void IndeterminateOutcome_maps_to_Indeterminate()
	{
		CategoryOf(IdentityOutcomeMap.ToOutcome(Failed(NorseIdentityErrorCodes.IndeterminateOutcome), Unit.Value))
			.ShouldBe(ErrorCategory.Indeterminate);
		IdentityOutcomeMap.TryClassify(new IndeterminateWriteException("a commit", new TimeoutException()),
			out var problem).ShouldBeTrue();
		problem.Category.ShouldBe(ErrorCategory.Indeterminate);
	}

	[Fact]
	void KeyDestroyedException_is_classified_as_Erased()
	{
		KeyDestroyedException destroyed = new(_receipt);

		IdentityOutcomeMap.IsErased(destroyed).ShouldBeTrue();
		IdentityOutcomeMap.IsErased(new InvalidOperationException()).ShouldBeFalse();
		IdentityOutcomeMap.TryClassify(destroyed, out var problem).ShouldBeTrue();
		problem.Category.ShouldBe(ErrorCategory.Erased);
		problem.Receipt.ShouldBe(_receipt);
	}

	[Fact]
	void OpenIddict_concurrency_maps_to_Conflict()
	{
		IdentityOutcomeMap.TryClassify(new OpenIddictExceptions.ConcurrencyException("stale"), out var conflict)
			.ShouldBeTrue();
		conflict.Category.ShouldBe(ErrorCategory.Conflict);
		IdentityOutcomeMap.TryClassify(new OpenIddictExceptions.ValidationException("ID2113"), out var fault)
			.ShouldBeTrue();
		fault.Category.ShouldBe(ErrorCategory.Fault);
	}

	[Fact]
	void Refused_methods_map_to_Fault_and_unclassified_exceptions_propagate()
	{
		IdentityOutcomeMap.TryClassify(new NotSupportedException("refused"), out var refused).ShouldBeTrue();
		refused.Category.ShouldBe(ErrorCategory.Fault);
		IdentityOutcomeMap.TryClassify(new InvalidOperationException("a bug"), out _).ShouldBeFalse();
	}

	[Fact]
	void A_mixed_failure_answers_its_gravest_category_and_keys_errors_by_code()
	{
		var outcome = IdentityOutcomeMap.ToOutcome(
			Failed(nameof(IdentityErrorDescriber.PasswordTooShort), nameof(IdentityErrorDescriber.DuplicateEmail),
				nameof(IdentityErrorDescriber.PasswordTooShort)), Unit.Value);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Conflict);
		failed.Problem.Errors.Keys.ShouldBe(
			[nameof(IdentityErrorDescriber.PasswordTooShort), nameof(IdentityErrorDescriber.DuplicateEmail)],
			ignoreOrder: true);
		failed.Problem.Errors[nameof(IdentityErrorDescriber.PasswordTooShort)].Length.ShouldBe(2);
	}

	[Fact]
	void A_succeeded_result_carries_the_value()
	{
		var outcome = IdentityOutcomeMap.ToOutcome(IdentityResult.Success, 42);

		outcome.TryGetValue(out Success<int> success).ShouldBeTrue();
		success.Value.ShouldBe(42);
	}

	[Fact]
	void SignInResult_states_map_to_completion_or_category()
	{
		Completion(IdentityOutcomeMap.ToOutcome(SignInResult.Success)).ShouldBe(SignInCompletion.SignedIn);
		Completion(IdentityOutcomeMap.ToOutcome(SignInResult.TwoFactorRequired))
			.ShouldBe(SignInCompletion.RequiresTwoFactor);
		CategoryOf(IdentityOutcomeMap.ToOutcome(SignInResult.LockedOut)).ShouldBe(ErrorCategory.LockedOut);
		CategoryOf(IdentityOutcomeMap.ToOutcome(SignInResult.NotAllowed)).ShouldBe(ErrorCategory.NotAllowed);
		CategoryOf(IdentityOutcomeMap.ToOutcome(SignInResult.Failed)).ShouldBe(ErrorCategory.InvalidCredentials);
	}

	static IdentityResult Failed(params string[] codes) =>
		IdentityResult.Failed([.. codes.Select(static code => new IdentityError { Code = code, Description = code })]);

	static ErrorCategory CategoryOf<T>(Outcome<T> outcome)
		where T : notnull
	{
		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		return failed.Problem.Category;
	}

	static SignInCompletion Completion(Outcome<SignInCompletion> outcome)
	{
		outcome.TryGetValue(out Success<SignInCompletion> success).ShouldBeTrue();
		return success.Value;
	}

	static object? DummyArgument(ParameterInfo parameter) =>
		parameter.ParameterType == typeof(int) ?
			1 :
			"x";
}
