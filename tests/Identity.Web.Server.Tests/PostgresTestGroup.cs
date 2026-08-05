namespace Norse.Identity.Web.Server.Tests;

/// <summary>
/// Declares <see cref="PostgresIdentityFixture"/> as a shared collection fixture: every test class
/// that needs it opts in via <c>[Collection(Name)]</c> and takes it as a constructor parameter,
/// never via its own <c>IClassFixture&lt;PostgresIdentityFixture&gt;</c> -- exactly one instance (one
/// host, one <c>IPersonalDataProtector</c>, one Postgres container, one keys directory) for every
/// class in the collection, never one per class. See <see cref="PostgresIdentityFixture"/>'s own
/// remark for why a second in-process instance is a bug, not a tolerance.
/// </summary>
[CollectionDefinition(Name)]
public sealed class PostgresTestGroup : ICollectionFixture<PostgresIdentityFixture>
{
	/// <summary>The collection name every real-Postgres test class opts into via <c>[Collection(Name)]</c>.</summary>
	public const string Name = "Postgres";
}
