using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthenticationAPI.Migrations
{
    /// <inheritdoc />
    public partial class AddMfaColumnsToAspNetUsers : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Add MFA columns if missing
            migrationBuilder.Sql(@"
IF COL_LENGTH('dbo.AspNetUsers', 'MfaEnabled') IS NULL
BEGIN
    ALTER TABLE dbo.AspNetUsers ADD MfaEnabled bit NOT NULL CONSTRAINT DF_AspNetUsers_MfaEnabled DEFAULT(0) WITH VALUES;
END;
IF COL_LENGTH('dbo.AspNetUsers', 'MfaSecret') IS NULL
BEGIN
    ALTER TABLE dbo.AspNetUsers ADD MfaSecret nvarchar(max) NULL;
END;
IF COL_LENGTH('dbo.AspNetUsers', 'MfaLastTimeStep') IS NULL
BEGIN
    ALTER TABLE dbo.AspNetUsers ADD MfaLastTimeStep bigint NOT NULL CONSTRAINT DF_AspNetUsers_MfaLastTimeStep DEFAULT(-1) WITH VALUES;
END;

-- Normalize defaults to desired values
DECLARE @hasDefault bit = 0;
SELECT @hasDefault = CASE WHEN dc.[name] IS NOT NULL THEN 1 ELSE 0 END
FROM sys.default_constraints dc
JOIN sys.columns c ON c.default_object_id = dc.object_id
JOIN sys.objects o ON o.object_id = c.object_id AND o.[name] = 'AspNetUsers'
WHERE c.[name] = 'MfaEnabled';
IF (@hasDefault = 0)
BEGIN
    ALTER TABLE dbo.AspNetUsers ADD CONSTRAINT DF_AspNetUsers_MfaEnabled DEFAULT(0) FOR MfaEnabled;
END;

SELECT @hasDefault = 0;
SELECT @hasDefault = CASE WHEN dc.[name] IS NOT NULL THEN 1 ELSE 0 END
FROM sys.default_constraints dc
JOIN sys.columns c ON c.default_object_id = dc.object_id
JOIN sys.objects o ON o.object_id = c.object_id AND o.[name] = 'AspNetUsers'
WHERE c.[name] = 'MfaLastTimeStep';
IF (@hasDefault = 0)
BEGIN
    ALTER TABLE dbo.AspNetUsers ADD CONSTRAINT DF_AspNetUsers_MfaLastTimeStep DEFAULT(-1) FOR MfaLastTimeStep;
END;

");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Drop added columns if present
            migrationBuilder.Sql(@"
IF COL_LENGTH('dbo.AspNetUsers', 'MfaEnabled') IS NOT NULL
BEGIN
    DECLARE @df1 sysname;
    SELECT @df1 = dc.[name]
    FROM sys.default_constraints dc
    JOIN sys.columns c ON c.default_object_id = dc.object_id
    JOIN sys.objects o ON o.object_id = c.object_id AND o.[name] = 'AspNetUsers'
    WHERE c.[name] = 'MfaEnabled';
    IF @df1 IS NOT NULL EXEC('ALTER TABLE dbo.AspNetUsers DROP CONSTRAINT ' + QUOTENAME(@df1));
    ALTER TABLE dbo.AspNetUsers DROP COLUMN MfaEnabled;
END;
IF COL_LENGTH('dbo.AspNetUsers', 'MfaSecret') IS NOT NULL
BEGIN
    ALTER TABLE dbo.AspNetUsers DROP COLUMN MfaSecret;
END;
IF COL_LENGTH('dbo.AspNetUsers', 'MfaLastTimeStep') IS NOT NULL
BEGIN
    DECLARE @df2 sysname;
    SELECT @df2 = dc.[name]
    FROM sys.default_constraints dc
    JOIN sys.columns c ON c.default_object_id = dc.object_id
    JOIN sys.objects o ON o.object_id = c.object_id AND o.[name] = 'AspNetUsers'
    WHERE c.[name] = 'MfaLastTimeStep';
    IF @df2 IS NOT NULL EXEC('ALTER TABLE dbo.AspNetUsers DROP CONSTRAINT ' + QUOTENAME(@df2));
    ALTER TABLE dbo.AspNetUsers DROP COLUMN MfaLastTimeStep;
END;
");
        }
    }
}
