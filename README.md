# AuthenticationAPI

A production-ready ASP.NET Core 9 authentication API with:
- ASP.NET Identity + EF Core (SQL Server)
- Argon2id password hashing
- JWT (RS256) with key rotation + JWKS endpoint
- Refresh tokens, roles/permissions (scope claims), optional TOTP MFA
- Rate limiting, correlation IDs, audit & idempotency middleware

## Setup
1. Copy `.env.example` to `.env` and update values.
2. Ensure SQL Server (Express) is running.
3. Apply migrations and run.

## Try it
```powershell
# build
DotNet build

# apply migrations
DotNet ef database update

# run
DotNet run --project .\AuthenticationAPI.csproj
```

Swagger UI: https://localhost:7086/swagger

Admin seed (DEV): reads `SeedAdmin__Email` and `SeedAdmin__Password` from `.env`.

## Notes
- For production, set real environment variables instead of `.env`.
- To enable real email, implement `IEmailSender` and wire SMTP settings in `.env`.