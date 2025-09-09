using Microsoft.EntityFrameworkCore.Migrations;

namespace AuthenticationAPI.Migrations
{
    [Migration("20250908141000_AddConsentColumns")]
    public partial class AddConsentColumns : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            var sql = @"
IF COL_LENGTH('dbo.AspNetUsers','TermsAcceptedUtc') IS NULL
BEGIN
    ALTER TABLE dbo.AspNetUsers ADD TermsAcceptedUtc datetime2 NULL;
END
IF COL_LENGTH('dbo.AspNetUsers','MarketingOptInUtc') IS NULL
BEGIN
    ALTER TABLE dbo.AspNetUsers ADD MarketingOptInUtc datetime2 NULL;
END
";
            migrationBuilder.Sql(sql);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            var sql = @"
IF COL_LENGTH('dbo.AspNetUsers','TermsAcceptedUtc') IS NOT NULL
BEGIN
    ALTER TABLE dbo.AspNetUsers DROP COLUMN TermsAcceptedUtc;
END
IF COL_LENGTH('dbo.AspNetUsers','MarketingOptInUtc') IS NOT NULL
BEGIN
    ALTER TABLE dbo.AspNetUsers DROP COLUMN MarketingOptInUtc;
END
";
            migrationBuilder.Sql(sql);
        }
    }
}
