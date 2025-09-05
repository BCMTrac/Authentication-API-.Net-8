# Authentication API (BCM Track)

Purpose

- Provide a secure, company-grade authentication and authorization service for all BCM Track apps.
- Centralize identity, tokens, roles/permissions, and security controls.

Key capabilities (high level)

- Secure password storage using Argon2id (modern standard)
- JWT access tokens (asymmetric RSA/RS256) with key rotation and JWKS endpoint
- Refresh tokens for session continuity (revoke on demand)
- Role-based access plus fine-grained permissions exposed as scope claims
- Optional Multi-Factor Authentication (TOTP)
- Password reset and email confirmation workflows
- Operational guards: rate limiting, correlation IDs, audit logs, idempotency

What this enables for BCM Track

- Single, consistent sign-in across services
- Easy API integration via standard JWT validation
- Fine-grained authorization by declaring required scopes
- Transparent key rotation without service restarts

How it works (broad, non-technical)

- Users sign in with username + password. If MFA is enabled, they add a one-time code from an authenticator app.
- The API issues a short-lived access token and a longer-lived refresh token.
- Apps call other services with the access token. Services validate the token and read role/permission “scopes”.
- When the access token expires, the client uses the refresh token to get a new one without re-entering credentials.
- Admins can reset passwords, confirm emails, and revoke refresh tokens at any time.

Main endpoints (examples)

- POST /api/authenticate/login — sign in, returns access + refresh tokens
- POST /api/authenticate/refresh — exchange refresh token for a new access token
- POST /api/authenticate/request-password-reset — sends reset token to user email
- POST /api/authenticate/confirm-password-reset — applies the reset using the token
- POST /api/authenticate/request-email-confirm — sends confirmation token
- POST /api/authenticate/confirm-email — confirms email using the token
- POST /api/authenticate/mfa/enroll/start — returns a secret + QR URL to enroll
- POST /api/authenticate/mfa/enroll/confirm — verifies code and enables MFA
- POST /api/authenticate/mfa/disable — disables MFA
- GET /.well-known/jwks.json — publishes public signing keys for token verification

Multi-factor authentication (TOTP)

- Users enroll by scanning a QR code (or using the raw secret) in an authenticator app (Google/Microsoft Authenticator, etc.).
- On login, if MFA is enabled, the user submits the 6-digit code. If it matches, login succeeds.

What’s still to add (future hardening)

- Production email provider (current default logs to console; Mailtrap API supported for testing)
- Admin UI and self-service profile pages
- Swagger protection in production + stricter CORS
- Security monitoring dashboards and alerting

Setup

1. Copy `.env.example` to `.env` and customize values (DB, JWT, CORS, email).
2. Ensure SQL Server (Express) is running.
3. Apply migrations and run.

Try it

```powershell
# build
dotnet build

# apply migrations
dotnet ef database update

# run
dotnet run --project .\AuthenticationAPI.csproj
```

Swagger UI: https://localhost:7086/swagger

Notes

- For production, use real environment variables or a secrets manager instead of `.env`.
- For email during testing, set a Mailtrap API token in `.env` and the API will send via Mailtrap.
