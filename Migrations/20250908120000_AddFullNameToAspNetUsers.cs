using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure; // for [DbContext] attribute
using AuthenticationAPI.Data;

#nullable disable

namespace AuthenticationAPI.Migrations
{
    /// <inheritdoc />
    [DbContext(typeof(ApplicationDbContext))]
    [Migration("20250908120000_AddFullNameToAspNetUsers")]
    public partial class AddFullNameToAspNetUsers : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
IF COL_LENGTH('dbo.AspNetUsers', 'FullName') IS NULL
BEGIN
    ALTER TABLE dbo.AspNetUsers ADD FullName nvarchar(100) NULL;
END;
");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.Sql(@"
IF COL_LENGTH('dbo.AspNetUsers', 'FullName') IS NOT NULL
BEGIN
    ALTER TABLE dbo.AspNetUsers DROP COLUMN FullName;
END;
");
        }
    }
}
