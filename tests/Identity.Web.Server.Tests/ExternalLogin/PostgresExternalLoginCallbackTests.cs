namespace Norse.Identity.Web.Server.Tests.ExternalLogin;

/// <summary><see cref="ExternalLoginCallbackSuite" /> over <c>postgres:19rc1</c>.</summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresExternalLoginCallbackTests(PostgresIdentityFixture fixture) : ExternalLoginCallbackSuite(fixture);
