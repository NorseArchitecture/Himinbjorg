using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     Email is the username (2026-10-24 explicit-writes spec §3.1), once per provider: every write path that sets
///     an email sets the username and both lookup hashes with it, in one operation and one <c>users</c> history
///     version, and the username is never set on its own.
/// </summary>
/// <remarks>
///     <para>
///         The lookup hashes are read raw from whichever table the model maps each to, so one body serves the
///         principal table and the <c>user_credentials</c> fragment alike, under both providers' naming.
///     </para>
///     <para>
///         Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///         records: xUnit discovers them on each <see langword="sealed" /> provider class.
///     </para>
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class EmailIsUserNameSuite(IdentityFixture fixture)
{
	/// <summary>
	///     The <c>SkipUnless</c> gate. True here, which is right for Postgres; a provider class whose container a
	///     host cannot run hides it with its own.
	/// </summary>
	public static bool IsTestable => true;

	/// <summary>The skip reason for a host that cannot run the provider's container.</summary>
	protected const string UntestableReason = "Requires a running Docker daemon on a host other than Windows on ARM.";

	/// <summary>The current test's cancellation token.</summary>
	protected static CancellationToken Cancellation => TestContext.Current.CancellationToken;

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task SetEmail_sets_username_and_both_hashes_in_one_operation()
	{
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("set-email-before@example.com");
		var (context, _) = await fixture.CreateScopeAsync();
		var before = await LookupHashesAsync(context, user.Id);
		var userManager = fixture.CreateUserManager();
		var reloaded = (await userManager.FindByIdAsync(user.Id.ToString())).ShouldNotBeNull();

		(await userManager.SetEmailAsync(reloaded, "set-email-after@example.com")).Succeeded.ShouldBeTrue();

		(await UserVersionsAsync(context, user.Id)).ShouldBe(1, "one operation, one users history version");
		var after = await LookupHashesAsync(context, user.Id);
		after.NormalizedEmail.ShouldNotBe(before.NormalizedEmail);
		after.NormalizedUserName.ShouldBe(after.NormalizedEmail);
		await ShouldReadBackAsync(user.Id, "set-email-after@example.com");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task ChangeEmail_through_the_confirmation_flow_writes_one_version_with_equal_hashes()
	{
		// The calls ConfirmEmailChange.razor makes: a change-email token minted for the new address, then
		// ChangeEmailAsync alone -- the page's second, SetUserNameAsync call is gone.
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("change-email-before@example.com", "+15550130");
		var userManager = fixture.CreateUserManager();
		var reloaded = (await userManager.FindByIdAsync(user.Id.ToString())).ShouldNotBeNull();
		var newEmail = "change-email-after@example.com";
		var token = await userManager.GenerateChangeEmailTokenAsync(reloaded, newEmail);
		var (context, _) = await fixture.CreateScopeAsync();
		var phoneBefore = (await RawColumnAsync(context, nameof(NorseUser.PhoneNumber), user.Id)).ShouldNotBeNull();

		(await userManager.ChangeEmailAsync(reloaded, newEmail, token)).Succeeded.ShouldBeTrue();

		(await UserVersionsAsync(context, user.Id)).ShouldBe(1, "one operation, one users history version");
		var after = await LookupHashesAsync(context, user.Id);
		after.NormalizedUserName.ShouldBe(after.NormalizedEmail);
		(await RawColumnAsync(context, nameof(NorseUser.PhoneNumber), user.Id)).ShouldBe(phoneBefore,
			"the unchanged PhoneNumber ciphertext never appears in the SET clause");
		await ShouldReadBackAsync(user.Id, newEmail);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task SetUserName_is_refused()
	{
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("set-username@example.com");
		var userManager = fixture.CreateUserManager();
		var reloaded = (await userManager.FindByIdAsync(user.Id.ToString())).ShouldNotBeNull();
		var (context, _) = await fixture.CreateScopeAsync();

		var result = await userManager.SetUserNameAsync(reloaded, "someone-else@example.com");

		result.Succeeded.ShouldBeFalse();
		result.Errors.Single().Code.ShouldBe(NorseUserManager.UserNameIsDerivedErrorCode);
		reloaded.UserName.ShouldBe("set-username@example.com", "a refusal leaves the instance untouched");
		(await UserVersionsAsync(context, user.Id)).ShouldBe(0, "a refusal writes nothing");
		await ShouldReadBackAsync(user.Id, "set-username@example.com");
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task External_login_registration_writes_equal_hashes()
	{
		// ExternalLogin.razor's OnValidSubmitAsync: both values set through the store's setters on a new
		// instance, then CreateAsync and AddLoginAsync through the manager.
		fixture.SkipUnlessAvailable();
		var email = "external-login@example.com";
		var store = fixture.CreateUserStore();
		var emailStore = (IUserEmailStore<NorseUser>)store;
		NorseUser user = new();
		await store.SetUserNameAsync(user, email, Cancellation);
		await emailStore.SetEmailAsync(user, email, Cancellation);
		var userManager = fixture.CreateUserManager();

		(await userManager.CreateAsync(user)).Succeeded.ShouldBeTrue();
		(await userManager.AddLoginAsync(user, new("TestProvider", $"key-{user.Id:N}", "Test"))).Succeeded
			.ShouldBeTrue();

		var (context, _) = await fixture.CreateScopeAsync();
		var hashes = await LookupHashesAsync(context, user.Id);
		hashes.NormalizedEmail.ShouldNotBeNullOrEmpty();
		hashes.NormalizedUserName.ShouldBe(hashes.NormalizedEmail);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task An_email_less_create_is_refused_with_InvalidEmail_and_writes_no_row()
	{
		// Email is the username, and both lookup hashes are NOT NULL, so a user without an email is
		// unrepresentable. RequireUniqueEmail makes Identity's own UserValidator say so as an IdentityResult,
		// before any write, rather than leaving the database to refuse it as an exception.
		fixture.SkipUnlessAvailable();
		var userManager = fixture.CreateUserManager();
		NorseUser user = new() { UserName = "no-email-user" };

		var result = await userManager.CreateAsync(user);

		result.Succeeded.ShouldBeFalse();
		result.Errors.Select(static error => error.Code).ShouldBe([nameof(IdentityErrorDescriber.InvalidEmail)]);
		var (context, _) = await fixture.CreateScopeAsync();
		(await context.Users.AnyAsync(u => u.Id == user.Id, Cancellation)).ShouldBeFalse("a refusal writes nothing");
	}

	/// <summary>How many superseded versions of one user row the history holds.</summary>
	protected abstract Task<long> UserVersionsAsync(NorseIdentityDbContext context, Guid userId);

	async Task ShouldReadBackAsync(Guid userId, string email)
	{
		var stored = (await fixture.CreateUserManager().FindByIdAsync(userId.ToString())).ShouldNotBeNull();
		stored.Email.ShouldBe(email);
		stored.UserName.ShouldBe(email);
	}

	static async Task<(string? NormalizedEmail, string? NormalizedUserName)> LookupHashesAsync(
		NorseIdentityDbContext context, Guid userId) =>
		(await RawColumnAsync(context, nameof(NorseUser.NormalizedEmail), userId),
			await RawColumnAsync(context, nameof(NorseUser.NormalizedUserName), userId));

	/// <summary>One user's raw column value, from whichever table -- principal or fragment -- the model maps it to.</summary>
	static Task<string?> RawColumnAsync(NorseIdentityDbContext context, string propertyName, Guid userId)
	{
		var users = context.Users.EntityType;
		var sql = context.GetService<ISqlGenerationHelper>();
		var (table, column) = new[] { StoreObjectIdentifier.Table(users.GetTableName().ShouldNotBeNull(), users.GetSchema()) }
			.Concat(users.GetMappingFragments().Select(static fragment => fragment.StoreObject))
			.Select(storeObject => (StoreObject: storeObject, Column: users.GetProperty(propertyName).GetColumnName(storeObject)))
			.Single(static mapping => mapping.Column is not null);
		var idColumn = sql.DelimitIdentifier(users.GetProperty(nameof(NorseUser.Id)).GetColumnName(table).ShouldNotBeNull());
		var select =
			$"SELECT {sql.DelimitIdentifier(column!)} AS {sql.DelimitIdentifier("Value")} FROM {sql.DelimitIdentifier(table.Name, table.Schema)} WHERE {idColumn} = {{0}}";
		return context.Database
			.SqlQueryRaw<string?>(select, userId)
			.SingleAsync(Cancellation);
	}
}
