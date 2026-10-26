using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     The database's own defense of <em>email is the username</em> (2026-10-24 explicit-writes spec §3.1), once per
///     provider over the checked-in <c>InitialCreate</c>: the <c>user_credentials</c> fragment refuses any raw write
///     that breaks its <c>CHECK (normalized_email = normalized_user_name)</c> or either hash's <c>NOT NULL</c>.
/// </summary>
/// <remarks>
///     <para>
///         The writes are raw, below Identity, on purpose: the manager already writes equal hashes on every path
///         (<see cref="EmailIsUserNameSuite" />), so only a write that bypasses it can prove the backstop. Table
///         and column names come from the model and are delimited by the provider, so one body serves both; only
///         the catalog reads and the engine's error codes are the provider's. Every write targets a user the test
///         seeded itself. That the constraint and the NOT NULLs exist where they should, and nowhere else, is a
///         catalog fact with its own home per provider: <c>NorseIdentityTemporalApparatusContainerTests</c> in
///         <c>Identity.Migrations.Tests</c> on Postgres, <see cref="SqlServerIdentitySchemaTests" /> on SQL Server.
///     </para>
///     <para>
///         Test methods are <see langword="protected" /> for the reason <see cref="TemporalIdentityVersioningSuite" />
///         records: xUnit discovers them on each <see langword="sealed" /> provider class.
///     </para>
/// </remarks>
/// <param name="fixture">The provider's shared real-database, real-DI fixture.</param>
public abstract class UserCredentialsConstraintSuite(IdentityFixture fixture)
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

	/// <summary>The fragment's check constraint, by the name a violation reports.</summary>
	protected abstract string CheckConstraintName { get; }

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Direct_write_of_equal_hashes_succeeds()
	{
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("credentials-conforming@example.com");
		var (context, _) = await fixture.CreateScopeAsync();

		(await WriteHashesAsync(context, user.Id, "conforming", "conforming")).ShouldBe(1);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Direct_write_of_unequal_hashes_is_rejected_by_CHECK()
	{
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("credentials-unequal@example.com");
		var (context, _) = await fixture.CreateScopeAsync();

		var refusal = await Should.ThrowAsync<DbException>(() =>
			WriteHashesAsync(context, user.Id, "the-email-hash", "another-user-name-hash"));

		IsCheckViolation(refusal, CheckConstraintName).ShouldBeTrue(refusal.Message);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Direct_write_of_null_email_hash_is_rejected()
	{
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("credentials-null-email@example.com");
		var (context, _) = await fixture.CreateScopeAsync();

		// NOT NULL is load-bearing: a CHECK comparing to NULL evaluates to unknown, and unknown passes.
		var refusal = await Should.ThrowAsync<DbException>(() =>
			WriteHashesAsync(context, user.Id, null, "a-user-name-hash"));

		IsNotNullViolation(refusal).ShouldBeTrue(refusal.Message);
	}

	[Fact(SkipUnless = nameof(IsTestable), Skip = UntestableReason)]
	protected async Task Direct_write_of_both_hashes_null_is_rejected()
	{
		fixture.SkipUnlessAvailable();
		var user = await fixture.SeedUserAsync("credentials-null-both@example.com");
		var (context, _) = await fixture.CreateScopeAsync();

		var refusal = await Should.ThrowAsync<DbException>(() => WriteHashesAsync(context, user.Id, null, null));

		IsNotNullViolation(refusal).ShouldBeTrue(refusal.Message);
	}

	/// <summary>Whether the engine refused a write for breaking the named check constraint.</summary>
	protected abstract bool IsCheckViolation(DbException exception, string constraint);

	/// <summary>Whether the engine refused a write for putting <c>NULL</c> in a <c>NOT NULL</c> column.</summary>
	protected abstract bool IsNotNullViolation(DbException exception);

	static (StoreObjectIdentifier Users, StoreObjectIdentifier Credentials) Tables(NorseIdentityDbContext context)
	{
		var users = context.Users.EntityType;
		return (StoreObjectIdentifier.Table(users.GetTableName().ShouldNotBeNull(), users.GetSchema()),
			users.GetMappingFragments().Single().StoreObject);
	}

	/// <summary>
	///     Writes both lookup hashes of one user straight into the fragment, bypassing Identity. A null hash is
	///     written as the literal <c>NULL</c>: an untyped null parameter is refused client-side, before the engine
	///     could refuse the write itself.
	/// </summary>
	static Task<int> WriteHashesAsync(NorseIdentityDbContext context, Guid userId, string? normalizedEmail,
		string? normalizedUserName)
	{
		var users = context.Users.EntityType;
		var (_, credentials) = Tables(context);
		var sql = context.GetService<ISqlGenerationHelper>();
		string Column(string property) =>
			sql.DelimitIdentifier(users.GetProperty(property).GetColumnName(credentials).ShouldNotBeNull());
		List<object> parameters = [userId];
		string Value(string? hash)
		{
			if (hash is null)
				return "NULL";
			parameters.Add(hash);
			return $"{{{parameters.Count - 1}}}";
		}

		var update =
			$"UPDATE {sql.DelimitIdentifier(credentials.Name, credentials.Schema)} SET {Column(nameof(NorseUser.NormalizedEmail))} = {Value(normalizedEmail)}, {Column(nameof(NorseUser.NormalizedUserName))} = {Value(normalizedUserName)} WHERE {Column(nameof(NorseUser.Id))} = {{0}}";
		return context.Database.ExecuteSqlRawAsync(update, parameters, Cancellation);
	}
}
