# BCMTrac Authentication Service – Production Guide

This is the independent authentication/authorization service for BCMTrac. It issues JWT access tokens, manages refresh/session state, supports MFA, and provides RBAC + permission scopes. It also bridges to the legacy .NET 4 monolith via YARP by emitting legacy-compatible session identifiers.

Overview

- Identity: ASP.NET Core Identity with Argon2id password hashing
- Tokens: RS256 JWTs, rolling key-ring with JWKS publishing
- Sessions: First-class sessions mapped to refresh tokens; rotation + reuse detection
- MFA: TOTP (QR code enrollment, recovery codes)
- RBAC/Scopes: Roles (Identity) + Permission table; scopes added to JWT
- UI: Static login/reset/confirm pages + Admin panel (interim; SPA migration planned)
- Bridge: Response headers for YARP to transform into legacy cookies + session info endpoint
- Hardening: CORS lock-down, HSTS/HTTPS, CSP, rate limiting, audit + idempotency

Key Endpoints

- POST /api/v1/authenticate/login — Sign in, returns access + refresh & emits bridge headers
- POST /api/v1/authenticate/refresh — Refresh token rotation; reuse detection; rate limited
- POST /api/v1/authenticate/logout — Revoke current session; clears cookie if enabled
- POST /api/v1/authenticate/logout-all — Revoke all sessions for user
- POST /api/v1/authenticate/request-password-reset — Email reset link
- POST /api/v1/authenticate/confirm-password-reset — Reset using token
- POST /api/v1/authenticate/request-email-confirm — Email confirmation link
- POST /api/v1/authenticate/confirm-email — Confirm email
- POST /api/v1/authenticate/mfa/enroll/start — Generate secret + otpauth:// URL
- POST /api/v1/authenticate/mfa/enroll/confirm — Verify code, enable MFA, issue recovery codes
- POST /api/v1/authenticate/mfa/disable — Disable (requires amr=mfa)
- POST /api/v1/authenticate/mfa/recovery/regenerate — New codes (requires amr=mfa)
- GET /api/v1/mfa/qr?otpauthUrl=... — QR code image for enrollment
- GET /.well-known/jwks.json — Public keys
- GET /api/v1/bridge/session/{sid} — Session → user/roles/scopes for legacy filter (API-key required)

Bridge to Legacy via YARP

- Configure YARP to route auth endpoints to this service; monolith remains default.
- On login/refresh, this service emits:
  - X-Legacy-Session-1/2/3: the sid (Session.Id GUID as string)
  - X-Auth-JWT (optional): current access token
- YARP transforms those headers into Set-Cookie for the legacy app.
- The monolith uses a new filter to read cookies, call /api/v1/bridge/session/{sid} with X-Bridge-Api-Key, and construct the principal.

Security Defaults

- CORS: locked to Cors:AllowedOrigins (semicolon-separated). Required in prod.
- HTTPS/HSTS enabled in prod; X-Forwarded headers honored
- CSP strict in prod; dev allows ws:// for tools
- Rate limiting policies on login/otp/refresh
- Refresh tokens: optional HttpOnly cookie mode (RefreshTokens:UseCookie=true) with CORS credentials

Configuration

- appsettings.json (Production):
  - JWT:ValidIssuer, JWT:ValidAudience
  - Cors:AllowedOrigins
  - PasswordHistory (Keep, ReuseWindow, MinAgeHours)
  - Email:EmailConfirm:Url, PasswordReset:Url
  - RefreshTokens:UseCookie (recommended true in prod)
  - Bridge (Enabled, ApiKeyHeader, ApiKey, HeaderNames, JwtHeaderName)
  - Throttle (Provider: memory|redis, RedisConnectionString via env)
  - Features (Swagger=false, AutoMigrate=false, Seed=false)

- appsettings.Development.json: local URLs; MinAge=0 for passwords; refresh cookie off.

- .env (examples in .env.example):
  - Cors__AllowedOrigins
  - Throttle__Provider=redis and Throttle__RedisConnectionString for distributed rate limiting
  - DataProtection__Storage=azure plus Azure__Blob__ConnectionString, Azure__Blob__Container, Azure__KeyVault__VaultUrl, Azure__KeyVault__KeyId
  - SMTP settings

Azure Key Vault & Data Protection

- If Azure:KeyVault:VaultUrl is set, config loads secrets from Key Vault via Managed Identity or DefaultAzureCredential.
- If DataProtection:Storage=azure, keys are persisted to Azure Blob and protected by a Key Vault key.

Password Policy & Behavior

- Access tokens ~15 minutes; refresh rotates on each refresh with reuse detection.
- Password reuse blocked for last 3 changes (configurable).
- Min password age: 24h in prod, 0 in dev.
- On password change/reset, sessions are revoked and token version increments.

Admin Panel (interim)

- Static admin at /admin (requires Admin role). Features:
  - Search users; view profile flags; roles management; lock/unlock; email confirm/resend; disable MFA; set temp password; view/revoke sessions.
- SPA migration planned (React/Vue) with pagination, audit viewer, client-app management.

Testing & CI

- xUnit tests under tests/AuthenticationAPI.Tests (TotpService, RecoveryCodeService samples).
- GitHub Actions workflow .github/workflows/ci.yml builds and runs tests on PRs and pushes.

Running Locally

1. Copy .env.example to .env and fill values (DB, SMTP, CORS).
2. Run SQL Server.
3. dotnet build
4. Apply migrations if enabled via Features:AutoMigrate=true or run dotnet ef database update for both contexts.
5. dotnet run --project ./AuthenticationAPI.csproj
6. UI: /index.html (login), /admin (admin), /email-confirm.html, /reset-password.html.

YARP Transform (sketch)

On responses from auth service login/refresh routes:

- Read headers X-Legacy-Session-1/2/3 and set 3 cookies expected by the monolith:
  - Set-Cookie: SchemeCookie=<sid>; Path=/; Secure; HttpOnly; SameSite=None
  - Set-Cookie: AdminBackOfficeCookie=<sid>; ...
  - Set-Cookie: AnotherCookie=<sid>; ...
- Optionally set JWT cookie from X-Auth-JWT.

Production Notes

- Do NOT keep secrets in appsettings or repo. Use environment variables or Key Vault.
- For multi-node, set Throttle Provider to redis and set connection string.
- For Linux or scale-out, use DataProtection:Storage=azure to share key ring.
- Consider Serilog + OpenTelemetry for logs/metrics to your platform of choice.
