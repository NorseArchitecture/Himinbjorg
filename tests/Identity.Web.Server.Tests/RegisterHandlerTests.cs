using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Norse.Abstractions.Contracts;
using Norse.AuthN.Services;
using Norse.Identity.EntityFramework;
using Norse.Persistence.EntityFramework;
using Norse.Primitives;

namespace Norse.Identity.Web.Server.Tests;

public sealed class RegisterHandlerTests
{
	static NorseIdentityDbContext CreateContext()
	{
		var optionsBuilder = new DbContextOptionsBuilder<NorseIdentityDbContext>().UseSqlite("DataSource=:memory:");
		optionsBuilder.ApplyNorseTrackingBehavior();
		var options = optionsBuilder.Options;
		NorseIdentityDbContext context = new(options);
		context.Database.OpenConnection();
		context.Database.EnsureCreated();
		return context;
	}

	// Store is constructed and disposed by the caller (each Fact owns it via `using`) rather than
	// inside this helper — CA2000's dataflow analysis cannot see ownership transfer through
	// UserManager's constructor, so the store must be explicitly disposed where it's created.
	// NorseUserStore's inherited Dispose() (UserStoreBase) is idempotent, so UserManager's own
	// internal Store.Dispose() call on teardown is harmless to double up with.
	//
	// Real PasswordValidator<NorseUser> wired in (not an empty array) so a weak-but-non-duplicate
	// password actually produces IdentityResult errors — needed to test the Validation-vs-Conflict
	// categorization below meaningfully, not just narrate it in a comment.
	static UserManager<NorseUser> CreateUserManager(NorseUserStore store) =>
		new(store, null!, new PasswordHasher<NorseUser>(),
			[new UserValidator<NorseUser>()], [new PasswordValidator<NorseUser>()], new UpperInvariantLookupNormalizer(), new IdentityErrorDescriber(),
			null!, NullLogger<UserManager<NorseUser>>.Instance);

	// Rejection-of-an-invalid-request coverage moved to Midgard's ValidationBehavior tests —
	// ValidationBehavior owns validation now, RegisterHandler never sees an invalid request.

	[Fact]
	async Task Creates_a_NorseUser_for_a_valid_request()
	{
		await using var context = CreateContext();
		using NorseUserStore store = new(context, new IdentityErrorDescriber());
		using var userManager = CreateUserManager(store);
		RegisterHandler handler = new(userManager);
		RegisterCommand command = new(new RegisterRequest { EmailInput = "user@example.com", Password = "correct-horse-battery-1A!" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Success<NavigationResult> success).ShouldBeTrue();
		success.Value.NextUrl.ShouldBe("/Account/Login");
		(await context.Users.SingleAsync(TestContext.Current.CancellationToken)).Email.ShouldBe("user@example.com");
	}

	[Fact]
	async Task Rejects_a_duplicate_email_as_Conflict()
	{
		await using var context = CreateContext();
		using NorseUserStore store = new(context, new IdentityErrorDescriber());
		using var userManager = CreateUserManager(store);
		RegisterHandler handler = new(userManager);
		RegisterCommand command = new(new RegisterRequest { EmailInput = "user@example.com", Password = "correct-horse-battery-1A!" });
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
		await using var context = CreateContext();
		using NorseUserStore store = new(context, new IdentityErrorDescriber());
		using var userManager = CreateUserManager(store);
		RegisterHandler handler = new(userManager);
		// Passes FluentValidation's client-side MinimumLength(8) but fails ASP.NET Identity's default
		// password-complexity rules (needs a digit, an uppercase letter, a non-alphanumeric char) —
		// exercises the corrected mapping: this must be Validation, never Conflict.
		RegisterCommand command = new(new RegisterRequest { EmailInput = "user2@example.com", Password = "aaaaaaaa" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Category.ShouldBe(ErrorCategory.Validation);
	}

	[Fact]
	async Task Groups_every_password_policy_violation_under_the_Password_field_not_the_raw_Identity_error_code()
	{
		await using var context = CreateContext();
		using NorseUserStore store = new(context, new IdentityErrorDescriber());
		using var userManager = CreateUserManager(store);
		RegisterHandler handler = new(userManager);
		// "aaaaaaaa" fails four separate default Identity rules at once (digit, upper, non-alphanumeric,
		// unique-chars is fine here but the other three aren't) -- each mints its own IdentityError with
		// a distinct .Code ("PasswordRequiresDigit", "PasswordRequiresUpper", ...). Reproduced live: all
		// of them must collapse onto the single "Password" key, never survive as separate raw codes.
		RegisterCommand command = new(new RegisterRequest { EmailInput = "user3@example.com", Password = "aaaaaaaa" });

		var outcome = await handler.Handle(command, TestContext.Current.CancellationToken);

		outcome.TryGetValue(out Failed failed).ShouldBeTrue();
		failed.Problem.Errors.Keys.ShouldBe([nameof(RegisterRequest.Password)]);
		failed.Problem.Errors[nameof(RegisterRequest.Password)].Length.ShouldBeGreaterThan(1);
	}
}
