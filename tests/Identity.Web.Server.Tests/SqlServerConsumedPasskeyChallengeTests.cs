using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="ConsumedPasskeyChallengeSuite" /> over SQL Server 2025.</summary>
/// <param name="fixture">The shared real-SQL Server, real-DI fixture.</param>
[Collection(SqlServerTestGroup.Name)]
public sealed class SqlServerConsumedPasskeyChallengeTests(SqlServerIdentityFixture fixture)
	: ConsumedPasskeyChallengeSuite(fixture)
{
	public static new bool IsTestable => SqlServerIdentityFixture.IsTestable;

	// max_length is in bytes: nvarchar(64) reads 128, datetimeoffset(7) reads 10.
	protected override IReadOnlyList<string> ExpectedCatalog =>
	[
		"column ConsumedPasskeyChallenges.ChallengeHash binary(32) not null",
		"column ConsumedPasskeyChallenges.ExpiresAt datetimeoffset(10) not null",
		"column VerificationCursors.LastId uniqueidentifier(16) null",
		"column VerificationCursors.Name nvarchar(128) not null",
		"column VerificationCursors.UpdatedAt datetimeoffset(10) not null",
		"column VerificationCursors.Version bigint(8) not null",
		"index ConsumedPasskeyChallenges.IX_ConsumedPasskeyChallenges_ExpiresAt unique=0 (ExpiresAt)",
		"primary ConsumedPasskeyChallenges.PK_ConsumedPasskeyChallenges unique=1 (ChallengeHash)",
		"primary VerificationCursors.PK_VerificationCursors unique=1 (Name)"
	];

	protected override Task<List<string>> CatalogAsync(NorseIdentityDbContext context) =>
		context.Database.SqlQuery<string>(
			$"""
			SELECT entry AS Value FROM (
				SELECT CONCAT(CASE WHEN i.is_primary_key = 1 THEN N'primary ' ELSE N'index ' END, t.name, N'.', i.name,
					N' unique=', i.is_unique, N' (', STRING_AGG(c.name, N',') WITHIN GROUP (ORDER BY ic.key_ordinal), N')') AS entry
				FROM sys.tables t
					JOIN sys.indexes i ON i.object_id = t.object_id
					JOIN sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
					JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
				WHERE t.name IN (N'ConsumedPasskeyChallenges', N'VerificationCursors') AND ic.key_ordinal > 0
				GROUP BY t.name, i.name, i.is_primary_key, i.is_unique
				UNION ALL
				SELECT CONCAT(N'column ', t.name, N'.', c.name, N' ', TYPE_NAME(c.user_type_id), N'(', c.max_length, N') ',
					CASE WHEN c.is_nullable = 1 THEN N'null' ELSE N'not null' END)
				FROM sys.tables t JOIN sys.columns c ON c.object_id = t.object_id
				WHERE t.name IN (N'ConsumedPasskeyChallenges', N'VerificationCursors')
			) catalog
			ORDER BY entry COLLATE Latin1_General_100_BIN2
			""").ToListAsync(Cancellation);
}
