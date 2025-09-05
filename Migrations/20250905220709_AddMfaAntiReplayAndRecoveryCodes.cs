using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthenticationAPI.Migrations
{
    /// <inheritdoc />
    public partial class AddMfaAntiReplayAndRecoveryCodes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "MfaLastTimeStep",
                table: "AspNetUsers",
                type: "bigint",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.CreateTable(
                name: "UserRecoveryCodes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    UserId = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    CodeHash = table.Column<string>(type: "nvarchar(450)", nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    RedeemedUtc = table.Column<DateTime>(type: "datetime2", nullable: true),
                    RedeemedIp = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_UserRecoveryCodes", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_UserRecoveryCodes_UserId_CodeHash",
                table: "UserRecoveryCodes",
                columns: new[] { "UserId", "CodeHash" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "UserRecoveryCodes");

            migrationBuilder.DropColumn(
                name: "MfaLastTimeStep",
                table: "AspNetUsers");
        }
    }
}
