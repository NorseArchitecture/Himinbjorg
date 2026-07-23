using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Norse.Identity.Migrations.SqlServer.Migrations;

/// <inheritdoc />
public partial class _20260723080838_InitialCreate : Migration
{
    /// <inheritdoc />
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "Applications",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                ApplicationType = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                ClientId = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true),
                ClientSecret = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                ClientType = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                ConcurrencyToken = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                ConsentType = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                DisplayName = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                DisplayNames = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                JsonWebKeySet = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                Permissions = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                PostLogoutRedirectUris = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                Properties = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                RedirectUris = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                Requirements = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                Settings = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Applications", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "Roles",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                Name = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                NormalizedName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                ConcurrencyStamp = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Roles", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "Scopes",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                ConcurrencyToken = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                Description = table.Column<string>(type: "nvarchar(1000)", maxLength: 1000, nullable: true),
                Descriptions = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                DisplayName = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                DisplayNames = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                Name = table.Column<string>(type: "nvarchar(200)", maxLength: 200, nullable: true),
                Properties = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                Resources = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Scopes", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "Users",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                SecurityStamp = table.Column<string>(type: "nchar(32)", fixedLength: true, maxLength: 32, nullable: false),
                UserName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                NormalizedUserName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                Email = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                NormalizedEmail = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                EmailConfirmed = table.Column<bool>(type: "bit", nullable: false),
                PasswordHash = table.Column<byte[]>(type: "varbinary(128)", maxLength: 128, nullable: true),
                ConcurrencyStamp = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                PhoneNumber = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: true),
                PhoneNumberConfirmed = table.Column<bool>(type: "bit", nullable: false),
                TwoFactorEnabled = table.Column<bool>(type: "bit", nullable: false),
                LockoutEnd = table.Column<DateTimeOffset>(type: "datetimeoffset", nullable: true),
                LockoutEnabled = table.Column<bool>(type: "bit", nullable: false),
                AccessFailedCount = table.Column<int>(type: "int", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Users", x => x.Id);
            });

        migrationBuilder.CreateTable(
            name: "Authorizations",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                ApplicationId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                ConcurrencyToken = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                CreationDate = table.Column<DateTime>(type: "datetime2", nullable: true),
                Properties = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                Scopes = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                Status = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                Subject = table.Column<string>(type: "nvarchar(400)", maxLength: 400, nullable: true),
                Type = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Authorizations", x => x.Id);
                table.ForeignKey(
                    name: "FK_Authorizations_Applications_ApplicationId",
                    column: x => x.ApplicationId,
                    principalTable: "Applications",
                    principalColumn: "Id");
            });

        migrationBuilder.CreateTable(
            name: "RoleClaims",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                ClaimType = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                ClaimValue = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_RoleClaims", x => x.Id);
                table.ForeignKey(
                    name: "FK_RoleClaims_Roles_RoleId",
                    column: x => x.RoleId,
                    principalTable: "Roles",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "UserClaims",
            columns: table => new
            {
                Id = table.Column<int>(type: "int", nullable: false)
                    .Annotation("SqlServer:Identity", "1, 1"),
                UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                ClaimType = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                ClaimValue = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_UserClaims", x => x.Id);
                table.ForeignKey(
                    name: "FK_UserClaims_Users_UserId",
                    column: x => x.UserId,
                    principalTable: "Users",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "UserLogins",
            columns: table => new
            {
                LoginProvider = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                ProviderKey = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: false),
                ProviderDisplayName = table.Column<string>(type: "nvarchar(256)", maxLength: 256, nullable: true),
                UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_UserLogins", x => new { x.LoginProvider, x.ProviderKey });
                table.ForeignKey(
                    name: "FK_UserLogins_Users_UserId",
                    column: x => x.UserId,
                    principalTable: "Users",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "UserPasskeys",
            columns: table => new
            {
                CredentialId = table.Column<byte[]>(type: "varbinary(1024)", maxLength: 1024, nullable: false),
                UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                Data = table.Column<string>(type: "json", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_UserPasskeys", x => x.CredentialId);
                table.ForeignKey(
                    name: "FK_UserPasskeys_Users_UserId",
                    column: x => x.UserId,
                    principalTable: "Users",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "UserRoles",
            columns: table => new
            {
                UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                RoleId = table.Column<Guid>(type: "uniqueidentifier", nullable: false)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_UserRoles", x => new { x.UserId, x.RoleId });
                table.ForeignKey(
                    name: "FK_UserRoles_Roles_RoleId",
                    column: x => x.RoleId,
                    principalTable: "Roles",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
                table.ForeignKey(
                    name: "FK_UserRoles_Users_UserId",
                    column: x => x.UserId,
                    principalTable: "Users",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "UserTokens",
            columns: table => new
            {
                UserId = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                LoginProvider = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                Name = table.Column<string>(type: "nvarchar(128)", maxLength: 128, nullable: false),
                Value = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_UserTokens", x => new { x.UserId, x.LoginProvider, x.Name });
                table.ForeignKey(
                    name: "FK_UserTokens_Users_UserId",
                    column: x => x.UserId,
                    principalTable: "Users",
                    principalColumn: "Id",
                    onDelete: ReferentialAction.Cascade);
            });

        migrationBuilder.CreateTable(
            name: "Tokens",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                ApplicationId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                AuthorizationId = table.Column<Guid>(type: "uniqueidentifier", nullable: true),
                ConcurrencyToken = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                CreationDate = table.Column<DateTime>(type: "datetime2", nullable: true),
                ExpirationDate = table.Column<DateTime>(type: "datetime2", nullable: true),
                Payload = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                Properties = table.Column<string>(type: "nvarchar(max)", maxLength: -1, nullable: true),
                RedemptionDate = table.Column<DateTime>(type: "datetime2", nullable: true),
                ReferenceId = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: true),
                Status = table.Column<string>(type: "nvarchar(50)", maxLength: 50, nullable: true),
                Subject = table.Column<string>(type: "nvarchar(400)", maxLength: 400, nullable: true),
                Type = table.Column<string>(type: "nvarchar(150)", maxLength: 150, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_Tokens", x => x.Id);
                table.ForeignKey(
                    name: "FK_Tokens_Applications_ApplicationId",
                    column: x => x.ApplicationId,
                    principalTable: "Applications",
                    principalColumn: "Id");
                table.ForeignKey(
                    name: "FK_Tokens_Authorizations_AuthorizationId",
                    column: x => x.AuthorizationId,
                    principalTable: "Authorizations",
                    principalColumn: "Id");
            });

        migrationBuilder.CreateIndex(
            name: "IX_Applications_ClientId",
            table: "Applications",
            column: "ClientId",
            unique: true,
            filter: "[ClientId] IS NOT NULL");

        migrationBuilder.CreateIndex(
            name: "IX_Authorizations_ApplicationId_Status_Subject_Type",
            table: "Authorizations",
            columns: new[] { "ApplicationId", "Status", "Subject", "Type" });

        migrationBuilder.CreateIndex(
            name: "IX_RoleClaims_RoleId",
            table: "RoleClaims",
            column: "RoleId");

        migrationBuilder.CreateIndex(
            name: "RoleNameIndex",
            table: "Roles",
            column: "NormalizedName",
            unique: true);

        migrationBuilder.CreateIndex(
            name: "IX_Scopes_Name",
            table: "Scopes",
            column: "Name",
            unique: true,
            filter: "[Name] IS NOT NULL");

        migrationBuilder.CreateIndex(
            name: "IX_Tokens_ApplicationId_Status_Subject_Type",
            table: "Tokens",
            columns: new[] { "ApplicationId", "Status", "Subject", "Type" });

        migrationBuilder.CreateIndex(
            name: "IX_Tokens_AuthorizationId",
            table: "Tokens",
            column: "AuthorizationId");

        migrationBuilder.CreateIndex(
            name: "IX_Tokens_ReferenceId",
            table: "Tokens",
            column: "ReferenceId",
            unique: true,
            filter: "[ReferenceId] IS NOT NULL");

        migrationBuilder.CreateIndex(
            name: "IX_UserClaims_UserId",
            table: "UserClaims",
            column: "UserId");

        migrationBuilder.CreateIndex(
            name: "IX_UserLogins_UserId",
            table: "UserLogins",
            column: "UserId");

        migrationBuilder.CreateIndex(
            name: "IX_UserPasskeys_UserId",
            table: "UserPasskeys",
            column: "UserId");

        migrationBuilder.CreateIndex(
            name: "IX_UserRoles_RoleId",
            table: "UserRoles",
            column: "RoleId");

        migrationBuilder.CreateIndex(
            name: "EmailIndex",
            table: "Users",
            column: "NormalizedEmail");

        migrationBuilder.CreateIndex(
            name: "UserNameIndex",
            table: "Users",
            column: "NormalizedUserName",
            unique: true);
    }

    /// <inheritdoc />
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(
            name: "RoleClaims");

        migrationBuilder.DropTable(
            name: "Scopes");

        migrationBuilder.DropTable(
            name: "Tokens");

        migrationBuilder.DropTable(
            name: "UserClaims");

        migrationBuilder.DropTable(
            name: "UserLogins");

        migrationBuilder.DropTable(
            name: "UserPasskeys");

        migrationBuilder.DropTable(
            name: "UserRoles");

        migrationBuilder.DropTable(
            name: "UserTokens");

        migrationBuilder.DropTable(
            name: "Authorizations");

        migrationBuilder.DropTable(
            name: "Roles");

        migrationBuilder.DropTable(
            name: "Users");

        migrationBuilder.DropTable(
            name: "Applications");
    }
}
