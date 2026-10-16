# Deployment and operations

## Environments and delivery

Development uses `bash scripts/dev-up.sh`; testing uses `npm run test:integration` with isolated database/cache containers. Staging and production use independent hosts, databases, volumes, credentials, encryption keys, billing secrets and SMTP accounts. Use `APP_ENV=staging` or `production`. Never enable billing simulation there; startup rejects it. Mailpit is a development profile only. Production SMTP should use authenticated TLS; production HTTPS is terminated by the host's ingress/load balancer in front of the loopback-bound reverse proxy.

CI runs type checking, formatting, unit/API tests, PostgreSQL/Redis integration tests, actual dependency outages, build, dependency audit and container smoke checks. No production deployment is automatic. The release workflow builds an immutable image after checks. Deployments run only on your separately provisioned staging/production runner, use protected GitHub environments and require an operator-supplied image tag/digest plus acceptance evidence. Configure production environment required reviewers and branch protections in GitHub; repository YAML alone cannot enforce those account settings.

On each target host, place a private `.env` (mode 0600) with the variables in `.env.example`, production SMTP and the environment-specific secrets. Install Docker/Compose, configure registry authentication and a TLS ingress, then run:

```bash
ATLANTIK_IMAGE=ghcr.io/your-org/atlantik@sha256:YOUR_DIGEST APP_ENV=staging bash scripts/deploy.sh
```

Migrations hold an advisory lock and run transactionally once per filename. The migration process alone holds the database superuser credential; application startup refuses elevated credentials. API/worker databases roles are provisioned by migrations. Re-run migrations to apply grants after schema changes. Inspect migration exit status before starting APIs. Existing migrations must not be edited after deployment; add a new file.

Use expand/contract schema changes compatible with the current and previous image. Roll back the application by rerunning deployment with the last accepted immutable image. Never automatically run a destructive down migration. The current additive schema has been exercised with application restart; a real staging rollback/restore drill remains a release gate. Keep the previous image available. Database restore and encryption-key recovery are coupled.

## Monitoring

`/health/live` checks only the API process. `/health/ready` checks PostgreSQL and Redis; the queue is PostgreSQL-backed. The protected `/api/v1/platform/health` includes worker/scheduler heartbeat timestamps and per-route request/error/latency aggregates. `/api/v1/platform/statistics` exposes organization counts and pending/dead job counts, without payloads. Alert on readiness failure, stale worker/scheduler heartbeats, rising error latency, dead letters, disk usage, PostgreSQL connections and repeated authentication failures. Export these signals into your organization's monitoring system; external metrics storage and distributed tracing are not preconfigured.

Workers claim one job at a time using `FOR UPDATE SKIP LOCKED`, holding the transaction until bounded delivery completes. Crashes release locks and preserve uncompleted jobs. At-least-once HTTP/email semantics require downstream deduplication. Scheduler passes run every 30 seconds under an advisory lock, and recurring reports/reminders have unique schedule-run keys. Failed passes roll back and retry at the next interval. Current scheduler scans active organizations; partition/batch this before operating at very large scale.

## Backup and recovery

Back up PostgreSQL with your managed service or scheduled `pg_dump`/WAL archiving. Encrypt backups and keep the application encryption key in an independent secret manager. Redis contains rate counters only; queue durability is in PostgreSQL. Retain audit logs according to a documented legal/customer retention policy. Test restores into an isolated environment, run migrations, verify row counts and tenant isolation, verify encrypted webhook/email payload recovery, and execute readiness/security tests before promotion. No destructive volume-deletion command is part of normal deployment.

## Troubleshooting

- API 503: inspect readiness, PostgreSQL/Redis health and structured logs using the response request ID. Never log connection strings or token/email payloads.
- API 401: verify session/key expiry/revocation, active user status and selected organization membership. Email verification is mandatory.
- API 403: inspect organization/subscription states and current role permissions. A platform administrator must explicitly belong to a customer tenant to use tenant APIs.
- Quota errors: inspect usage and plan limits; owners retain subscription recovery access. Do not bypass quotas by editing counters casually.
- Email/webhook backlog: inspect worker heartbeat and sanitized outbox/delivery metadata, SMTP/TLS, public DNS and outbound access. Dead letters stop after eight attempts; requeue only after the underlying cause is fixed and duplicate effects are understood.
- Encryption failures: recover the correct key; do not regenerate it. Pending jobs contain authenticated encrypted payloads.
- Non-root container cannot read files: verify Docker COPY ownership and mounted configuration permissions. Do not run the API as root to bypass this.
- Managed build cannot write buildx state: set `BUILDX_CONFIG=/tmp/atlantik-buildx` for the build command while preserving Docker registry credentials. When required, pass the managed CA as the `proxy_ca` build secret; do not disable TLS verification.

## Platform administrator provisioning

There is no public administrator signup. An authorized operator grants `platform_admin=true` to an already verified account through the migration/admin database connection and records the access approval outside the application. Revoke it the same way and revoke that user's sessions. Never promote a customer through a request field or ship a default administrator password.
