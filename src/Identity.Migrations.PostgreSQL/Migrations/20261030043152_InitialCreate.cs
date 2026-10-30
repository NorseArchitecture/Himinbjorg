using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Norse.Identity.Migrations.PostgreSQL.Migrations;

/// <inheritdoc />
public partial class _20261030043152_InitialCreate : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "applications",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                application_type = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                client_id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                client_secret = table.Column<string>(type: "text", maxLength: -1, nullable: true),
                client_type = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                concurrency_token = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                consent_type = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                display_name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                display_names = table.Column<string>(type: "text", maxLength: -1, nullable: true),
                json_web_key_set = table.Column<string>(type: "text", maxLength: -1, nullable: true),
                permissions = table.Column<string[]>(type: "text[]", nullable: true),
                post_logout_redirect_uris = table.Column<string[]>(type: "text[]", nullable: true),
                properties = table.Column<string>(type: "text", maxLength: -1, nullable: true),
                redirect_uris = table.Column<string[]>(type: "text[]", nullable: true),
                requirements = table.Column<string[]>(type: "text[]", nullable: true),
                settings = table.Column<string>(type: "text", maxLength: -1, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_applications", x => x.id);
            })
            .Annotation("Norse:Temporal", true);

        migrationBuilder.CreateTable(
            name: "consumed_passkey_challenges",
            columns: table => new
            {
                challenge_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_consumed_passkey_challenges", x => x.challenge_hash);
            });

        migrationBuilder.CreateTable(
            name: "resources",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                concurrency_token = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                description = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                descriptions = table.Column<string>(type: "text", maxLength: -1, nullable: true),
                display_name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                display_names = table.Column<string>(type: "text", maxLength: -1, nullable: true),
                name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                properties = table.Column<string>(type: "text", maxLength: -1, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_resources", x => x.id);
            })
            .Annotation("Norse:Temporal", true);

        migrationBuilder.CreateTable(
            name: "roles",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                normalized_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                concurrency_stamp = table.Column<Guid>(type: "uuid", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_roles", x => x.id);
            })
            .Annotation("Norse:Temporal", true);

        migrationBuilder.CreateTable(
            name: "scopes",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                concurrency_token = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                description = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                descriptions = table.Column<string>(type: "text", maxLength: -1, nullable: true),
                display_name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                display_names = table.Column<string>(type: "text", maxLength: -1, nullable: true),
                name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                properties = table.Column<string>(type: "text", maxLength: -1, nullable: true),
                resources = table.Column<string[]>(type: "text[]", nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_scopes", x => x.id);
            })
            .Annotation("Norse:Temporal", true);

        migrationBuilder.CreateTable(
            name: "subject_keys",
            columns: table => new
            {
                subject_id = table.Column<Guid>(type: "uuid", nullable: false),
                wrapped_key = table.Column<byte[]>(type: "bytea", maxLength: 64, nullable: false),
                wrapping_key_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_subject_keys", x => x.subject_id);
            });

        migrationBuilder.CreateTable(
            name: "users",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                user_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                email_confirmed = table.Column<bool>(type: "boolean", nullable: false),
                concurrency_stamp = table.Column<Guid>(type: "uuid", nullable: false),
                phone_number = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                phone_number_confirmed = table.Column<bool>(type: "boolean", nullable: false),
                two_factor_enabled = table.Column<bool>(type: "boolean", nullable: false),
                lockout_enabled = table.Column<bool>(type: "boolean", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_users", x => x.id);
            })
            .Annotation("Norse:Temporal", true);

        migrationBuilder.CreateTable(
            name: "verification_cursors",
            columns: table => new
            {
                name = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                last_id = table.Column<Guid>(type: "uuid", nullable: true),
                version = table.Column<long>(type: "bigint", nullable: false),
                updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_verification_cursors", x => x.name);
            });

        migrationBuilder.CreateTable(
            name: "authorizations",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                application_id = table.Column<Guid>(type: "uuid", nullable: true),
                concurrency_token = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                creation_date = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                properties = table.Column<string>(type: "text", maxLength: -1, nullable: true),
                scopes = table.Column<string[]>(type: "text[]", nullable: true),
                status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                subject = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: true),
                type = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_authorizations", x => x.id);
                table.ForeignKey(
                    name: "fk_authorizations_applications_application_id",
                    column: x => x.application_id,
                    principalTable: "applications",
                    principalColumn: "id");
            });

        migrationBuilder.CreateTable(
            name: "role_claims",
            columns: table => new
            {
                id = table.Column<int>(type: "integer", nullable: false)
                    .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                role_id = table.Column<Guid>(type: "uuid", nullable: false),
                claim_type = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                claim_value = table.Column<string>(type: "text", maxLength: -1, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_role_claims", x => x.id);
                table.ForeignKey(
                    name: "fk_role_claims_roles_role_id",
                    column: x => x.role_id,
                    principalTable: "roles",
                    principalColumn: "id",
                    onDelete: ReferentialAction.Cascade);
            })
            .Annotation("Norse:Temporal", true);

        migrationBuilder.CreateTable(
            name: "user_claims",
            columns: table => new
            {
                id = table.Column<int>(type: "integer", nullable: false)
                    .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                claim_value_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false, computedColumnSql: "norse_utf8_sha256(claim_value)", stored: true),
                user_id = table.Column<Guid>(type: "uuid", nullable: false),
                claim_type = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                claim_value = table.Column<string>(type: "text", maxLength: -1, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_user_claims", x => x.id);
                table.ForeignKey(
                    name: "fk_user_claims_users_user_id",
                    column: x => x.user_id,
                    principalTable: "users",
                    principalColumn: "id",
                    onDelete: ReferentialAction.Cascade);
            })
            .Annotation("Norse:Temporal", true);

        migrationBuilder.CreateTable(
            name: "user_credentials",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                security_stamp = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                normalized_user_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                normalized_email = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                password_hash = table.Column<byte[]>(type: "bytea", maxLength: 128, nullable: true),
                lockout_end = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                access_failed_count = table.Column<int>(type: "integer", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_user_credentials", x => x.id);
                table.ForeignKey(
                    name: "FK_user_credentials_users_id",
                    column: x => x.id,
                    principalTable: "users",
                    principalColumn: "id",
                    onDelete: ReferentialAction.Cascade);
            })
            .Annotation("Norse:FragmentCheckConstraint:ck_user_credentials_email_is_user_name", "normalized_email = normalized_user_name");

        migrationBuilder.CreateTable(
            name: "user_logins",
            columns: table => new
            {
                login_provider = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                provider_key = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                provider_display_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                user_id = table.Column<Guid>(type: "uuid", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_user_logins", x => new { x.login_provider, x.provider_key });
                table.ForeignKey(
                    name: "fk_user_logins_users_user_id",
                    column: x => x.user_id,
                    principalTable: "users",
                    principalColumn: "id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "user_passkeys",
            columns: table => new
            {
                credential_id = table.Column<byte[]>(type: "bytea", maxLength: 1024, nullable: false),
                user_id = table.Column<Guid>(type: "uuid", nullable: false),
                data = table.Column<string>(type: "jsonb", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_user_passkeys", x => x.credential_id);
                table.ForeignKey(
                    name: "fk_user_passkeys_users_user_id",
                    column: x => x.user_id,
                    principalTable: "users",
                    principalColumn: "id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "user_roles",
            columns: table => new
            {
                user_id = table.Column<Guid>(type: "uuid", nullable: false),
                role_id = table.Column<Guid>(type: "uuid", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_user_roles", x => new { x.user_id, x.role_id });
                table.ForeignKey(
                    name: "fk_user_roles_roles_role_id",
                    column: x => x.role_id,
                    principalTable: "roles",
                    principalColumn: "id",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "fk_user_roles_users_user_id",
                    column: x => x.user_id,
                    principalTable: "users",
                    principalColumn: "id",
                    onDelete: ReferentialAction.Cascade);
            })
            .Annotation("Norse:Temporal", true);

        migrationBuilder.CreateTable(
            name: "user_tokens",
            columns: table => new
            {
                user_id = table.Column<Guid>(type: "uuid", nullable: false),
                login_provider = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                name = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                value = table.Column<string>(type: "text", maxLength: -1, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_user_tokens", x => new { x.user_id, x.login_provider, x.name });
                table.ForeignKey(
                    name: "fk_user_tokens_users_user_id",
                    column: x => x.user_id,
                    principalTable: "users",
                    principalColumn: "id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "sessions",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                application_id = table.Column<Guid>(type: "uuid", nullable: true),
                authorization_id = table.Column<Guid>(type: "uuid", nullable: true),
                concurrency_token = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                creation_date = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                login_id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                properties = table.Column<string>(type: "text", maxLength: -1, nullable: true),
                status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                subject = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_sessions", x => x.id);
                table.ForeignKey(
                    name: "fk_sessions_applications_application_id",
                    column: x => x.application_id,
                    principalTable: "applications",
                    principalColumn: "id");
                table.ForeignKey(
                    name: "fk_sessions_authorizations_authorization_id",
                    column: x => x.authorization_id,
                    principalTable: "authorizations",
                    principalColumn: "id");
            });

        migrationBuilder.CreateTable(
            name: "tokens",
            columns: table => new
            {
                id = table.Column<Guid>(type: "uuid", nullable: false),
                application_id = table.Column<Guid>(type: "uuid", nullable: true),
                authorization_id = table.Column<Guid>(type: "uuid", nullable: true),
                session_id = table.Column<Guid>(type: "uuid", nullable: true),
                concurrency_token = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                creation_date = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                expiration_date = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                payload = table.Column<string>(type: "text", maxLength: -1, nullable: true),
                properties = table.Column<string>(type: "text", maxLength: -1, nullable: true),
                redemption_date = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                reference_id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: true),
                status = table.Column<string>(type: "character varying(50)", maxLength: 50, nullable: true),
                subject = table.Column<string>(type: "character varying(400)", maxLength: 400, nullable: true),
                type = table.Column<string>(type: "character varying(150)", maxLength: 150, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("pk_tokens", x => x.id);
                table.ForeignKey(
                    name: "fk_tokens_applications_application_id",
                    column: x => x.application_id,
                    principalTable: "applications",
                    principalColumn: "id");
                table.ForeignKey(
                    name: "fk_tokens_authorizations_authorization_id",
                    column: x => x.authorization_id,
                    principalTable: "authorizations",
                    principalColumn: "id");
                table.ForeignKey(
                    name: "fk_tokens_sessions_session_id",
                    column: x => x.session_id,
                    principalTable: "sessions",
                    principalColumn: "id");
            });

        migrationBuilder.CreateIndex(
            name: "ix_applications_client_id",
            table: "applications",
            column: "client_id",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "ix_authorizations_application_id_status_subject_type",
            table: "authorizations",
            columns: new[] { "application_id", "status", "subject", "type" });

        migrationBuilder.CreateIndex(
            name: "ix_consumed_passkey_challenges_expires_at",
            table: "consumed_passkey_challenges",
            column: "expires_at");

        migrationBuilder.CreateIndex(
            name: "ix_resources_name",
            table: "resources",
            column: "name",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "ix_role_claims_role_id",
            table: "role_claims",
            column: "role_id");

        migrationBuilder.CreateIndex(
            name: "role_name_index",
            table: "roles",
            column: "normalized_name",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "ix_scopes_name",
            table: "scopes",
            column: "name",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "ix_sessions_application_id",
            table: "sessions",
            column: "application_id");

        migrationBuilder.CreateIndex(
            name: "ix_sessions_authorization_id",
            table: "sessions",
            column: "authorization_id");

        migrationBuilder.CreateIndex(
            name: "ix_sessions_login_id",
            table: "sessions",
            column: "login_id");

        migrationBuilder.CreateIndex(
            name: "ix_tokens_application_id_status_subject_type",
            table: "tokens",
            columns: new[] { "application_id", "status", "subject", "type" });

        migrationBuilder.CreateIndex(
            name: "ix_tokens_authorization_id",
            table: "tokens",
            column: "authorization_id");

        migrationBuilder.CreateIndex(
            name: "ix_tokens_reference_id",
            table: "tokens",
            column: "reference_id",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "ix_tokens_session_id",
            table: "tokens",
            column: "session_id");

        migrationBuilder.CreateIndex(
            name: "ix_user_claims_user_id_claim_type_claim_value_hash",
            table: "user_claims",
            columns: new[] { "user_id", "claim_type", "claim_value_hash" },
            unique: true);

        migrationBuilder.CreateIndex(
            name: "email_index",
            table: "user_credentials",
            column: "normalized_email");

        migrationBuilder.CreateIndex(
            name: "user_name_index",
            table: "user_credentials",
            column: "normalized_user_name",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "ix_user_logins_user_id",
            table: "user_logins",
            column: "user_id");

        migrationBuilder.CreateIndex(
            name: "ix_user_passkeys_user_id",
            table: "user_passkeys",
            column: "user_id");

        migrationBuilder.CreateIndex(
            name: "ix_user_roles_role_id",
            table: "user_roles",
            column: "role_id");
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "consumed_passkey_challenges");

        migrationBuilder.DropTable(
            name: "resources")
            .Annotation("Norse:Temporal", true);

        migrationBuilder.DropTable(
            name: "role_claims")
            .Annotation("Norse:Temporal", true);

        migrationBuilder.DropTable(
            name: "scopes")
            .Annotation("Norse:Temporal", true);

        migrationBuilder.DropTable(
            name: "subject_keys");

        migrationBuilder.DropTable(
            name: "tokens");

        migrationBuilder.DropTable(
            name: "user_claims")
            .Annotation("Norse:Temporal", true);

        migrationBuilder.DropTable(
            name: "user_credentials");

        migrationBuilder.DropTable(
            name: "user_logins");

        migrationBuilder.DropTable(
            name: "user_passkeys");

        migrationBuilder.DropTable(
            name: "user_roles")
            .Annotation("Norse:Temporal", true);

        migrationBuilder.DropTable(
            name: "user_tokens");

        migrationBuilder.DropTable(
            name: "verification_cursors");

        migrationBuilder.DropTable(
            name: "sessions");

        migrationBuilder.DropTable(
            name: "roles")
            .Annotation("Norse:Temporal", true);

        migrationBuilder.DropTable(
            name: "users")
            .Annotation("Norse:Temporal", true);

        migrationBuilder.DropTable(
            name: "authorizations");

        migrationBuilder.DropTable(
            name: "applications")
            .Annotation("Norse:Temporal", true);
    }
}
