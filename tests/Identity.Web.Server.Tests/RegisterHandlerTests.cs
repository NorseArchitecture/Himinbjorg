using Microsoft.AspNetCore.Identity;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     <see cref="RegisterHandler" /> over the real registration surface: the DI-resolved
///     <see cref="NorseUserManager" />, with its validators and the PII protectors, on real Postgres. Every email is
///     this class's own, since the collection shares one database.
/// </summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class RegisterHandlerTests(PostgresIdentityFixture fixture)
{
	// Rejection-of-an-invalid-request coverage moved to Midgard's ValidationBehavior tests —
	// ValidationBehavior owns validation now, RegisterHandler never sees an invalid request.

	[Fact]
	async Task Creates_a_NorseUser_for_a_valid_request()
	{
		var userManager = fixture.CreateUserManager();
		RegisterHandler handler = new(userManager);
		RegisterCommand command =
			new(new RegisterRequest { EmailInput = "register-valid@example.com", Password = "correct-horse-battery-1A!" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldBe("/Account/Login");
		(await userManager.FindByEmailAsync("register-valid@example.com")).ShouldNotBeNull().UserName
			.ShouldBe("register-valid@example.com");
	}

	[Fact]
	async Task Rejects_a_duplicate_email_as_Conflict()
	{
		var userManager = fixture.CreateUserManager();
		RegisterHandler handler = new(userManager);
		RegisterCommand command =
			new(new RegisterRequest { EmailInput = "register-duplicate@example.com", Password = "correct-horse-battery-1A!" });
		await handler.Handle(command, TestContext.Current.CancellationToken);

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Conflict);
		// Reproduced live 2026-08-07: the client's ServerErrorCoordinator builds a FieldIdentifier
		// straight from these dictionary keys, so a raw IdentityError.Code like "DuplicateUserName"
		// renders nowhere — no bound field has that name, and the model-level summary only fires when
		// Errors is empty. The key here must be the wire field name the email input is bound to.
		failed.Problem.Errors.Keys.ShouldBe([nameof(RegisterRequest.Email)]);
	}

	[Fact]
	async Task Rejects_a_weak_but_non_duplicate_password_as_Validation_not_Conflict()
	{
		var userManager = fixture.CreateUserManager();
		RegisterHandler handler = new(userManager);
		// Passes FluentValidation's client-side MinimumLength(8) but fails ASP.NET Identity's default
		// password-complexity rules (needs a digit, an uppercase letter, a non-alphanumeric char) —
		// exercises the corrected mapping: this must be Validation, never Conflict.
		RegisterCommand command = new(new RegisterRequest { EmailInput = "register-weak@example.com", Password = "aaaaaaaa" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Validation);
	}

	[Fact]
	async Task Groups_every_password_policy_violation_under_the_Password_field_not_the_raw_Identity_error_code()
	{
		var userManager = fixture.CreateUserManager();
		RegisterHandler handler = new(userManager);
		// "aaaaaaaa" fails four separate default Identity rules at once (digit, upper, non-alphanumeric,
		// unique-chars is fine here but the other three aren't) -- each mints its own IdentityError with
		// a distinct .Code ("PasswordRequiresDigit", "PasswordRequiresUpper", ...). Reproduced live: all
		// of them must collapse onto the single "Password" key, never survive as separate raw codes.
		RegisterCommand command = new(new RegisterRequest { EmailInput = "register-policy@example.com", Password = "aaaaaaaa" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Errors.Keys.ShouldBe([nameof(RegisterRequest.Password)]);
		failed.Problem.Errors[nameof(RegisterRequest.Password)].Length.ShouldBeGreaterThan(1);
	}

	[Fact]
	async Task An_unclassified_failure_answers_Fault_not_Validation()
	{
		// The old "every non-duplicate failure is Validation" collapse is retired by design (explicit-writes spec
		// §4.12, ruled 2026-10-25): the one mapping table decides, and DefaultError is a Fault.
		using var userManager = MockUserManager.Create();
		userManager.CreateAsync(Arg.Any<NorseUser>(), Arg.Any<string>())
			.Returns(IdentityResult.Failed(new IdentityErrorDescriber().DefaultError()));
		RegisterHandler handler = new(userManager);

		var outcome = await handler.Handle(
			new(new RegisterRequest { EmailInput = "register-fault@example.com", Password = "correct-horse-battery-1A!" }),
			TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Fault);
		failed.Problem.Errors.Keys.ShouldBe([string.Empty]);
	}
}
