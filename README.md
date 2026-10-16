# Atlantik

A TypeScript, PostgreSQL and Redis backend for multi-tenant SaaS infrastructure. This repository implements the attached client specification under the Atlantik name. It is an acceptance-tested development foundation; production release still requires the operational gates in [progress](docs/progress.md).

## Run

Requires Node.js 24, Docker and Compose v2.24+.

```bash
bash scripts/dev-up.sh
```

This generates a private `.env` with random credentials, builds the non-root image, migrates PostgreSQL, provisions separate restricted API/worker roles, and starts API, PostgreSQL, Redis, worker, scheduler, reverse proxy and development email capture.

- API: http://localhost:8080
- OpenAPI: http://localhost:8080/openapi.json
- Email capture: http://localhost:8025
- Liveness: `/health/live`; dependency readiness: `/health/ready`

Register with `POST /api/v1/auth/register` using `name`, `email`, `password` (12–128 characters), `organization`, and `slug`. Copy the verification token from development email, send it to `POST /api/v1/auth/verify`, then log in. Tenant requests require `Authorization: Bearer <session>` and `X-Organization-Id: <organizationId>`. Email tokens and API secrets must never go in URLs.

```bash
npm ci
npm run check
npm run lint
npm test
npm run test:integration
npm run test:failures
npm run build
```

Integration/failure scripts use isolated Docker services on ports 55432/56379 and a database ending `_test`. Integration tests truncate that dedicated test database. Never point test credentials at staging or production. Local secrets are kept in ignored `.local/test.env`. `npm test` runs unit/API tests and explicitly skips external-service suites when integration configuration is absent.

For host-based development, supply `DATABASE_URL`, `REDIS_URL`, `APP_ENCRYPTION_KEY`, SMTP configuration and billing settings through your environment; run `npm run migrate` with the migration credential, then `npm run dev` with the restricted API credential. Workers use their separate database credential. Compose keeps database and Redis off public host ports.

## Documentation

- [Specification coverage and release gates](docs/progress.md)
- [Architecture and decisions](docs/architecture.md)
- [API behavior](docs/api.md), [endpoint catalog](docs/endpoints.md), [OpenAPI contract](docs/openapi.json)
- [Security boundaries](docs/security.md)
- [Deployment, recovery and troubleshooting](docs/operations.md)

A real payment provider is intentionally optional. Local development enables simulated subscriptions; staging/production require signed provider events and reject simulation mode. No external cloud deployment or payment-provider account is preconfigured.
