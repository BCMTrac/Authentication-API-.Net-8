using System;
using Microsoft.EntityFrameworkCore.Migrations;

namespace AuthenticationAPI.Migrations
{
    public partial class AddPublicKeyToSigningKeys : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "PublicKey",
                table: "SigningKeys",
                type: "nvarchar(max)",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PublicKey",
                table: "SigningKeys");
        }
    }
}