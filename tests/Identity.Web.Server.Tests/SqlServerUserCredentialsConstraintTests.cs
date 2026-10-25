using System.Data.Common;
using Microsoft.Data.SqlClient;

namespace Norse.Identity.Web.Server.Tests;

/// <summary>
///     <see cref="UserCredentialsConstraintSuite" /> over SQL Server 2025, recognizing the engine's error numbers.
/// </summary>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerUserCredentialsConstraintTests(SqlServerIdentityFixture fixture)
	: UserCredentialsConstraintSuite(fixture)
{
	// 547: a statement conflicted with a constraint; 515: NULL into a column that does not allow nulls.
	const int ConstraintConflict = 547;
	const int NullNotAllowed = 515;

	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;

	protected override string CheckConstraintName => "CK_UserCredentials_EmailIsUserName";

	protected override bool IsCheckViolation(DbException exception, string constraint) =>
		exception is SqlException { Number: ConstraintConflict } violation &&
		violation.Message.Contains($"\"{constraint}\"", StringComparison.Ordinal);

	protected override bool IsNotNullViolation(DbException exception) =>
		exception is SqlException { Number: NullNotAllowed };
}
