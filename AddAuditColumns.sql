IF OBJECT_ID(N'[__EFMigrationsHistory]') IS NULL
BEGIN
    CREATE TABLE [__EFMigrationsHistory] (
        [MigrationId] nvarchar(150) NOT NULL,
        [ProductVersion] nvarchar(32) NOT NULL,
        CONSTRAINT [PK___EFMigrationsHistory] PRIMARY KEY ([MigrationId])
    );
END;
GO

BEGIN TRANSACTION;
GO

CREATE TABLE [AspNetRoles] (
    [Id] nvarchar(128) NOT NULL,
    [Name] nvarchar(256) NULL,
    [NormalizedName] nvarchar(128) NULL,
    [ConcurrencyStamp] nvarchar(max) NULL,
    CONSTRAINT [PK_AspNetRoles] PRIMARY KEY ([Id])
);
GO

CREATE TABLE [AspNetUsers] (
    [Id] nvarchar(128) NOT NULL,
    [FullName] nvarchar(max) NULL,
    [TokenVersion] int NOT NULL,
    [MfaEnabled] bit NOT NULL,
    [MfaSecret] nvarchar(max) NULL,
    [MfaLastTimeStep] bigint NOT NULL,
    [UserName] nvarchar(256) NULL,
    [NormalizedUserName] nvarchar(128) NULL,
    [Email] nvarchar(256) NULL,
    [NormalizedEmail] nvarchar(128) NULL,
    [EmailConfirmed] bit NOT NULL,
    [PasswordHash] nvarchar(max) NULL,
    [SecurityStamp] nvarchar(max) NULL,
    [ConcurrencyStamp] nvarchar(max) NULL,
    [PhoneNumber] nvarchar(max) NULL,
    [PhoneNumberConfirmed] bit NOT NULL,
    [TwoFactorEnabled] bit NOT NULL,
    [LockoutEnd] datetimeoffset NULL,
    [LockoutEnabled] bit NOT NULL,
    [AccessFailedCount] int NOT NULL,
    CONSTRAINT [PK_AspNetUsers] PRIMARY KEY ([Id])
);
GO

CREATE TABLE [AuditLogs] (
    [Id] bigint NOT NULL IDENTITY,
    [TimestampUtc] datetime2 NOT NULL,
    [UserId] nvarchar(max) NULL,
    [UserName] nvarchar(max) NULL,
    [Action] nvarchar(100) NOT NULL,
    [TargetEntityType] nvarchar(100) NULL,
    [TargetEntityId] nvarchar(128) NULL,
    [Details] nvarchar(max) NULL,
    [Method] nvarchar(max) NOT NULL,
    [Path] nvarchar(max) NOT NULL,
    [StatusCode] int NOT NULL,
    [DurationMs] bigint NOT NULL,
    [CorrelationId] nvarchar(max) NULL,
    [ClientIp] nvarchar(max) NULL,
    CONSTRAINT [PK_AuditLogs] PRIMARY KEY ([Id])
);
GO

CREATE TABLE [IdempotencyRecords] (
    [Key] nvarchar(450) NOT NULL,
    [RequestHash] nvarchar(max) NOT NULL,
    [CreatedUtc] datetime2 NOT NULL,
    [StatusCode] int NOT NULL,
    [ResponseBody] nvarchar(max) NOT NULL,
    [ContentType] nvarchar(max) NOT NULL,
    [ExpiresUtc] datetime2 NULL,
    CONSTRAINT [PK_IdempotencyRecords] PRIMARY KEY ([Key])
);
GO

CREATE TABLE [SigningKeys] (
    [Id] uniqueidentifier NOT NULL,
    [Kid] nvarchar(40) NOT NULL,
    [Algorithm] nvarchar(max) NOT NULL,
    [Secret] nvarchar(max) NOT NULL,
    [PublicKey] nvarchar(max) NULL,
    [Active] bit NOT NULL,
    [CreatedUtc] datetime2 NOT NULL,
    [RetiredUtc] datetime2 NULL,
    CONSTRAINT [PK_SigningKeys] PRIMARY KEY ([Id])
);
GO

CREATE TABLE [UserRecoveryCodes] (
    [Id] int NOT NULL IDENTITY,
    [UserId] nvarchar(450) NOT NULL,
    [CodeHash] nvarchar(64) NOT NULL,
    [CreatedUtc] datetime2 NOT NULL,
    [RedeemedUtc] datetime2 NULL,
    [RedeemedIp] nvarchar(max) NULL,
    CONSTRAINT [PK_UserRecoveryCodes] PRIMARY KEY ([Id])
);
GO

CREATE TABLE [AspNetRoleClaims] (
    [Id] int NOT NULL IDENTITY,
    [RoleId] nvarchar(128) NOT NULL,
    [ClaimType] nvarchar(max) NULL,
    [ClaimValue] nvarchar(max) NULL,
    CONSTRAINT [PK_AspNetRoleClaims] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_AspNetRoleClaims_AspNetRoles_RoleId] FOREIGN KEY ([RoleId]) REFERENCES [AspNetRoles] ([Id]) ON DELETE CASCADE
);
GO

CREATE TABLE [AspNetUserClaims] (
    [Id] int NOT NULL IDENTITY,
    [UserId] nvarchar(128) NOT NULL,
    [ClaimType] nvarchar(max) NULL,
    [ClaimValue] nvarchar(max) NULL,
    CONSTRAINT [PK_AspNetUserClaims] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_AspNetUserClaims_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
);
GO

CREATE TABLE [AspNetUserLogins] (
    [LoginProvider] nvarchar(450) NOT NULL,
    [ProviderKey] nvarchar(450) NOT NULL,
    [ProviderDisplayName] nvarchar(max) NULL,
    [UserId] nvarchar(128) NOT NULL,
    CONSTRAINT [PK_AspNetUserLogins] PRIMARY KEY ([LoginProvider], [ProviderKey]),
    CONSTRAINT [FK_AspNetUserLogins_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
);
GO

CREATE TABLE [AspNetUserRoles] (
    [UserId] nvarchar(128) NOT NULL,
    [RoleId] nvarchar(128) NOT NULL,
    CONSTRAINT [PK_AspNetUserRoles] PRIMARY KEY ([UserId], [RoleId]),
    CONSTRAINT [FK_AspNetUserRoles_AspNetRoles_RoleId] FOREIGN KEY ([RoleId]) REFERENCES [AspNetRoles] ([Id]) ON DELETE CASCADE,
    CONSTRAINT [FK_AspNetUserRoles_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
);
GO

CREATE TABLE [AspNetUserTokens] (
    [UserId] nvarchar(128) NOT NULL,
    [LoginProvider] nvarchar(450) NOT NULL,
    [Name] nvarchar(450) NOT NULL,
    [Value] nvarchar(max) NULL,
    CONSTRAINT [PK_AspNetUserTokens] PRIMARY KEY ([UserId], [LoginProvider], [Name]),
    CONSTRAINT [FK_AspNetUserTokens_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
);
GO

CREATE TABLE [Sessions] (
    [Id] uniqueidentifier NOT NULL,
    [UserId] nvarchar(128) NOT NULL,
    [DeviceId] nvarchar(64) NULL,
    [Ip] nvarchar(64) NULL,
    [UserAgent] nvarchar(256) NULL,
    [CreatedUtc] datetime2 NOT NULL,
    [LastSeenUtc] datetime2 NULL,
    [RevokedAtUtc] datetime2 NULL,
    CONSTRAINT [PK_Sessions] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_Sessions_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
);
GO

CREATE TABLE [RefreshTokens] (
    [Id] uniqueidentifier NOT NULL,
    [UserId] nvarchar(128) NOT NULL,
    [TokenHash] nvarchar(64) NOT NULL,
    [ExpiresUtc] datetime2 NOT NULL,
    [CreatedUtc] datetime2 NOT NULL,
    [CreatedIp] nvarchar(max) NOT NULL,
    [SessionId] uniqueidentifier NULL,
    [RevokedUtc] datetime2 NULL,
    [RevokedReason] nvarchar(max) NULL,
    [ReplacedByTokenHash] nvarchar(64) NULL,
    [RowVersion] rowversion NULL,
    CONSTRAINT [PK_RefreshTokens] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_RefreshTokens_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE,
    CONSTRAINT [FK_RefreshTokens_Sessions_SessionId] FOREIGN KEY ([SessionId]) REFERENCES [Sessions] ([Id])
);
GO

CREATE INDEX [IX_AspNetRoleClaims_RoleId] ON [AspNetRoleClaims] ([RoleId]);
GO

CREATE UNIQUE INDEX [RoleNameIndex] ON [AspNetRoles] ([NormalizedName]) WHERE [NormalizedName] IS NOT NULL;
GO

CREATE INDEX [IX_AspNetUserClaims_UserId] ON [AspNetUserClaims] ([UserId]);
GO

CREATE INDEX [IX_AspNetUserLogins_UserId] ON [AspNetUserLogins] ([UserId]);
GO

CREATE INDEX [IX_AspNetUserRoles_RoleId] ON [AspNetUserRoles] ([RoleId]);
GO

CREATE INDEX [EmailIndex] ON [AspNetUsers] ([NormalizedEmail]);
GO

CREATE UNIQUE INDEX [UserNameIndex] ON [AspNetUsers] ([NormalizedUserName]) WHERE [NormalizedUserName] IS NOT NULL;
GO

CREATE INDEX [IX_IdempotencyRecords_CreatedUtc] ON [IdempotencyRecords] ([CreatedUtc]);
GO

CREATE INDEX [IX_RefreshTokens_SessionId] ON [RefreshTokens] ([SessionId]);
GO

CREATE UNIQUE INDEX [IX_RefreshTokens_UserId_TokenHash] ON [RefreshTokens] ([UserId], [TokenHash]);
GO

CREATE INDEX [IX_Sessions_UserId_CreatedUtc] ON [Sessions] ([UserId], [CreatedUtc]);
GO

CREATE UNIQUE INDEX [IX_SigningKeys_Kid] ON [SigningKeys] ([Kid]);
GO

CREATE UNIQUE INDEX [IX_UserRecoveryCodes_UserId_CodeHash] ON [UserRecoveryCodes] ([UserId], [CodeHash]);
GO

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250918224336_Initial', N'8.0.16');
GO

COMMIT;
GO

BEGIN TRANSACTION;
GO

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250919145244_AddAuditLogColumns', N'8.0.16');
GO

COMMIT;
GO

BEGIN TRANSACTION;
GO

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250919152455_AddMissingAuditLogColumns', N'8.0.16');
GO

COMMIT;
GO

