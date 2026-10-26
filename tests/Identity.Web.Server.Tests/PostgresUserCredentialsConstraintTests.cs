using System.Data.Common;
using Npgsql;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     <see cref="UserCredentialsConstraintSuite" /> over <c>postgres:19rc1</c>, recognizing the engine's SQLSTATEs.
/// </summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresUserCredentialsConstraintTests(PostgresIdentityFixture fixture)
	: UserCredentialsConstraintSuite(fixture)
{
	protected override string CheckConstraintName => "ck_user_credentials_email_is_user_name";

	protected override bool IsCheckViolation(DbException exception, string constraint) =>
		exception is PostgresException { SqlState: PostgresErrorCodes.CheckViolation } violation &&
		violation.ConstraintName == constraint;

	protected override bool IsNotNullViolation(DbException exception) =>
		exception is PostgresException { SqlState: PostgresErrorCodes.NotNullViolation };
}
