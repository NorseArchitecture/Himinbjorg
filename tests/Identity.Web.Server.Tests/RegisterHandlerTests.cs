using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Norse.Abstractions.Web.Server.Mediator;
using Norse.AuthN.Components;

namespace Norse.Identity.Web.Server.Tests;

public sealed class RegisterHandlerTests
{
	static NorseIdentityDbContext CreateContext()
	{
		var options = new DbContextOptionsBuilder<NorseIdentityDbContext>()
			.UseSqlite("DataSource=:memory:")
			.Options;
		var context = new NorseIdentityDbContext(options);
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

	[Fact]
	async Task Rejects_an_invalid_request_without_touching_the_store()
	{
		using var context = CreateContext();
		using var store = new NorseUserStore(context, new IdentityErrorDescriber());
		using var userManager = CreateUserManager(store);
		var handler = new RegisterHandler(userManager, new RegisterRequestValidator());
		var request = new RegisterRequest { Email = "not-an-email", Password = "short" };

		var outcome = await handler.Handle(request, CancellationToken.None);

		outcome.IsSuccess.ShouldBeFalse();
		outcome.Problem!.Category.ShouldBe(ErrorCategory.Validation);
		(await context.Users.CountAsync(TestContext.Current.CancellationToken)).ShouldBe(0);
	}

	[Fact]
	async Task Creates_a_NorseUser_for_a_valid_request()
	{
		using var context = CreateContext();
		using var store = new NorseUserStore(context, new IdentityErrorDescriber());
		using var userManager = CreateUserManager(store);
		var handler = new RegisterHandler(userManager, new RegisterRequestValidator());
		var request = new RegisterRequest { Email = "user@example.com", Password = "correct-horse-battery-1A!" };

		var outcome = await handler.Handle(request, CancellationToken.None);

		outcome.IsSuccess.ShouldBeTrue();
		outcome.Value!.Value.ShouldBeTrue();
		(await context.Users.SingleAsync(TestContext.Current.CancellationToken)).Email.ShouldBe("user@example.com");
	}

	[Fact]
	async Task Rejects_a_duplicate_email_as_Conflict()
	{
		using var context = CreateContext();
		using var store = new NorseUserStore(context, new IdentityErrorDescriber());
		using var userManager = CreateUserManager(store);
		var handler = new RegisterHandler(userManager, new RegisterRequestValidator());
		var request = new RegisterRequest { Email = "user@example.com", Password = "correct-horse-battery-1A!" };
		await handler.Handle(request, CancellationToken.None);

		var outcome = await handler.Handle(request, CancellationToken.None);

		outcome.IsSuccess.ShouldBeFalse();
		outcome.Problem!.Category.ShouldBe(ErrorCategory.Conflict);
	}

	[Fact]
	async Task Rejects_a_weak_but_non_duplicate_password_as_Validation_not_Conflict()
	{
		using var context = CreateContext();
		using var store = new NorseUserStore(context, new IdentityErrorDescriber());
		using var userManager = CreateUserManager(store);
		var handler = new RegisterHandler(userManager, new RegisterRequestValidator());
		// Passes FluentValidation's client-side MinimumLength(8) but fails ASP.NET Identity's default
		// password-complexity rules (needs a digit, an uppercase letter, a non-alphanumeric char) —
		// exercises the corrected mapping: this must be Validation, never Conflict.
		var request = new RegisterRequest { Email = "user2@example.com", Password = "aaaaaaaa" };

		var outcome = await handler.Handle(request, CancellationToken.None);

		outcome.IsSuccess.ShouldBeFalse();
		outcome.Problem!.Category.ShouldBe(ErrorCategory.Validation);
	}
}
