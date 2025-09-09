using Microsoft.EntityFrameworkCore.Migrations;

namespace AuthenticationAPI.Migrations
{
    [Migration("20250908141500_AddPasswordHistory")]
    public partial class AddPasswordHistory : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            var sql = @"
IF OBJECT_ID('dbo.PasswordHistory','U') IS NULL
BEGIN
    CREATE TABLE dbo.PasswordHistory (
        Id uniqueidentifier NOT NULL DEFAULT NEWID() PRIMARY KEY,
        UserId nvarchar(128) NOT NULL,
        Hash nvarchar(4000) NOT NULL,
        CreatedUtc datetime2 NOT NULL DEFAULT SYSUTCDATETIME()
    );
    CREATE INDEX IX_PasswordHistory_UserId_CreatedUtc ON dbo.PasswordHistory(UserId, CreatedUtc);
END
";
            migrationBuilder.Sql(sql);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            var sql = @"
IF OBJECT_ID('dbo.PasswordHistory','U') IS NOT NULL
BEGIN
    DROP TABLE dbo.PasswordHistory;
END
";
            migrationBuilder.Sql(sql);
        }
    }
}
