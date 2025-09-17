using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AuthenticationAPI.Migrations
{
    /// <inheritdoc />
    public partial class AddAuditLogColumns : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Only add missing AuditLogs columns; avoid altering AspNetUsers or other tables here.
            var sql = @"
IF COL_LENGTH('dbo.AuditLogs','Action') IS NULL
BEGIN
    ALTER TABLE dbo.AuditLogs ADD [Action] nvarchar(100) NOT NULL CONSTRAINT DF_AuditLogs_Action DEFAULT ('');
    ALTER TABLE dbo.AuditLogs DROP CONSTRAINT DF_AuditLogs_Action;
END
IF COL_LENGTH('dbo.AuditLogs','Details') IS NULL
BEGIN
    ALTER TABLE dbo.AuditLogs ADD [Details] nvarchar(max) NULL;
END
IF COL_LENGTH('dbo.AuditLogs','TargetEntityId') IS NULL
BEGIN
    ALTER TABLE dbo.AuditLogs ADD [TargetEntityId] nvarchar(128) NULL;
END
IF COL_LENGTH('dbo.AuditLogs','TargetEntityType') IS NULL
BEGIN
    ALTER TABLE dbo.AuditLogs ADD [TargetEntityType] nvarchar(100) NULL;
END
";
            migrationBuilder.Sql(sql);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Best-effort rollback of added AuditLogs columns
            var sql = @"
IF COL_LENGTH('dbo.AuditLogs','Action') IS NOT NULL
BEGIN
    ALTER TABLE dbo.AuditLogs DROP COLUMN [Action];
END
IF COL_LENGTH('dbo.AuditLogs','Details') IS NOT NULL
BEGIN
    ALTER TABLE dbo.AuditLogs DROP COLUMN [Details];
END
IF COL_LENGTH('dbo.AuditLogs','TargetEntityId') IS NOT NULL
BEGIN
    ALTER TABLE dbo.AuditLogs DROP COLUMN [TargetEntityId];
END
IF COL_LENGTH('dbo.AuditLogs','TargetEntityType') IS NOT NULL
BEGIN
    ALTER TABLE dbo.AuditLogs DROP COLUMN [TargetEntityType];
END
";
            migrationBuilder.Sql(sql);
        }
    }
}
