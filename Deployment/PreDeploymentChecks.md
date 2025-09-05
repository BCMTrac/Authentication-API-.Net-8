# Pre-deployment Checklist (Auth Service)

1. Pending EF Core migrations applied?
2. Database connectivity (read/write) validated.
3. Key store reachable & active signing key (kid) present.
4. Background services (rotation, outbox) healthy.
5. Rate limiting & security headers enabled in configuration.
6. Admin account seeded (or disabled for prod bootstrap strategy).
7. Secrets supplied via environment variables (no dev secrets file in container).
8. Connection string points to production database (verify host & db name).
9. Migration script dry-run executed (BEGIN TRAN + ROLLBACK) for size & lock time estimation.
10. Alerting endpoints (health, metrics) reachable.

Automated Script (future):

- dotnet ef migrations list -- checks no Unapplied
- Simple SQL: SELECT 1; (connectivity)
- Validate environment variables JWT**Secret, ConnectionStrings**DefaultConnection.
