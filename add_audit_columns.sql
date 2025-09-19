-- Add missing columns to AuditLogs table
ALTER TABLE [AuditLogs] ADD [Action] nvarchar(100) NOT NULL DEFAULT '';
ALTER TABLE [AuditLogs] ADD [Details] nvarchar(max) NULL;
ALTER TABLE [AuditLogs] ADD [TargetEntityId] nvarchar(128) NULL;
ALTER TABLE [AuditLogs] ADD [TargetEntityType] nvarchar(100) NULL;