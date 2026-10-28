using Microsoft.EntityFrameworkCore;
using Norse.Identity.EntityFramework;

namespace Norse.Identity.Web.Server.Tests;

/// <summary><see cref="ConsumedPasskeyChallengeSuite" /> over <c>postgres:19rc1</c>.</summary>
/// <param name="fixture">The shared real-Postgres, real-DI fixture.</param>
[Collection(PostgresTestGroup.Name)]
public sealed class PostgresConsumedPasskeyChallengeTests(PostgresIdentityFixture fixture)
	: ConsumedPasskeyChallengeSuite(fixture)
{
	protected override IReadOnlyList<string> ExpectedCatalog =>
	[
		"column consumed_passkey_challenges.challenge_hash bytea not null",
		"column consumed_passkey_challenges.expires_at timestamp with time zone not null",
		"column verification_cursors.last_id uuid null",
		"column verification_cursors.name character varying(64) not null",
		"column verification_cursors.updated_at timestamp with time zone not null",
		"column verification_cursors.version bigint not null",
		"index CREATE INDEX ix_consumed_passkey_challenges_expires_at ON public.consumed_passkey_challenges USING btree (expires_at)",
		"primary CREATE UNIQUE INDEX pk_consumed_passkey_challenges ON public.consumed_passkey_challenges USING btree (challenge_hash)",
		"primary CREATE UNIQUE INDEX pk_verification_cursors ON public.verification_cursors USING btree (name)"
	];

	protected override Task<List<string>> CatalogAsync(NorseIdentityDbContext context) =>
		context.Database.SqlQuery<string>(
			$"""
			SELECT entry AS "Value" FROM (
				SELECT format('%s %s', CASE WHEN i.indisprimary THEN 'primary' ELSE 'index' END,
					pg_catalog.pg_get_indexdef(i.indexrelid)) AS entry
				FROM pg_catalog.pg_index i
					JOIN pg_catalog.pg_class t ON t.oid = i.indrelid
					JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
				WHERE n.nspname = 'public' AND t.relname IN ('consumed_passkey_challenges', 'verification_cursors')
				UNION ALL
				SELECT format('column %s.%s %s %s', t.relname, a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod),
					CASE WHEN a.attnotnull THEN 'not null' ELSE 'null' END)
				FROM pg_catalog.pg_attribute a
					JOIN pg_catalog.pg_class t ON t.oid = a.attrelid
					JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
				WHERE n.nspname = 'public' AND t.relname IN ('consumed_passkey_challenges', 'verification_cursors')
					AND a.attnum > 0 AND NOT a.attisdropped
			) catalog
			ORDER BY entry COLLATE "C"
			""").ToListAsync(Cancellation);
}
