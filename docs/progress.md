# Atlantik requirements and verification checklist

Authoritative input: the supplied 10-page client specification, renamed Atlantik throughout the repository. The table follows its numbered requirements. **Implemented** describes working code; **tested** identifies executed evidence rather than implying every possible case has been covered. Production readiness is not claimed.

| Spec  | Requirement                                                  | Implementation                                            | Executed verification / outstanding work                                                                                                                                                                |
| ----- | ------------------------------------------------------------ | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1–2   | SaaS identity, user types, platform control plane            | Implemented                                               | Registration, owner/admin/member boundaries and platform-without-tenant access tested                                                                                                                   |
| 3     | Organization lifecycle, settings, ownership                  | Implemented                                               | Creation, listing isolation, ownership transfer with password confirmation, suspension/reactivation tested; deletion retention is documented                                                            |
| 4–6   | Accounts, verification, sessions, reset/profile              | Implemented                                               | Verification/replay/expiry, suspended users, session expiry, reset/revocation and real-email flow tested; profile, password/email-change, re-verification and logout after organization deletion tested |
| 7     | Tenant isolation                                             | Implemented in API, forced RLS and composite foreign keys | Cross-tenant API reads, role writes, guessed IDs, SQL reads/writes, organization settings isolation and foreign memberships tested                                                                      |
| 8     | Teams and multiple memberships                               | Implemented                                               | Team membership and inherited workspace access tested                                                                                                                                                   |
| 9     | Dynamic RBAC and resource authorization                      | Implemented                                               | Custom role assignment, denied owner-level grants, member/admin escalation and owner protection tested; immediate role edits/revocation and assigned-role deletion boundaries tested                    |
| 10    | Workspaces and membership ACL                                | Implemented                                               | Creation/read, direct/team ACL boundaries and concurrent resource quotas tested                                                                                                                         |
| 11    | Named scoped API keys, expiration, revocation, rotation      | Implemented                                               | Scope escalation, cross-tenant use, metadata secrecy, expiry, rotation and revocation tested                                                                                                            |
| 12    | Plan-bound usage metering                                    | Implemented                                               | Request quotas/recovery access, concurrent workspace limits, event deduplication, retained storage quotas/releases tested; Enterprise limits are operator-provisioned                                   |
| 13–14 | Subscription lifecycle and billing events                    | Implemented with provider adapter boundary                | Signed ingestion, duplicate IDs, stale versions, trial expiry, simulated plan change and billing privilege boundaries tested; real payment provider intentionally not configured                        |
| 15    | Signed webhooks, retries, history, disable                   | Implemented                                               | SSRF rules, fan-out, timeout adapter failure, retry/history, stable event IDs tested; live third-party HTTPS delivery remains an external acceptance check                                              |
| 16    | Email/in-app notifications                                   | Implemented                                               | Real SMTP verification delivery, encrypted email retry/recovery and notification business triggers present; not every template/trigger has an individual acceptance test                                |
| 17    | Append-only audits                                           | Implemented                                               | Successful/denied mutations, request-ID correlation, auth auditing and rejected audit rewriting tested                                                                                                  |
| 18    | Distributed rate limiting                                    | Implemented                                               | Excessive login attempts and Redis outage failure behavior tested; production ingress CIDR must be configured                                                                                           |
| 19–22 | Versioning, errors, request IDs, structured safe logging     | Implemented                                               | Versioned routes, 400/404/413/503 envelopes, request IDs and safe dependency failures tested                                                                                                            |
| 23    | Liveness/readiness and monitoring                            | Implemented                                               | Real database/cache failures and recovery tested; protected counters/queue statistics/heartbeats present; external alerting system not configured                                                       |
| 24–25 | Workers and recurring jobs                                   | Implemented                                               | Real stopped/restarted worker, terminated database connection, exponential retries, eight-attempt dead letters, schedule idempotency and expired trial cleanup tested                                   |
| 26–27 | Database integrity and security controls                     | Implemented                                               | Migrations, restricted roles, API inability to read queued secrets, forced RLS, owner uniqueness/membership, token/signature/SSRF security tests pass                                                   |
| 28–29 | Docker and separate environments                             | Implemented                                               | Non-root image, Compose startup, migrations, reverse proxy, worker, scheduler, SMTP, database/cache and API restart verified locally                                                                    |
| 30    | CI/CD                                                        | Implemented workflows and deployment scripts              | Local checks/build/audit/container flow pass; GitHub runs, registry publishing and staging/production deployment require a connected repository and runners                                             |
| 31    | Unit, integration, API, security, failure tests              | Implemented and executed                                  | 8 unit/API/security tests, 30 real-service integration tests, 3 actual outage tests, and Compose end-to-end smoke pass                                                                                  |
| 32    | API, architecture, ER, setup, deployment, security, runbooks | Implemented                                               | 74 endpoint operations documented in generated OpenAPI/catalog; diagrams, decisions and runbooks included                                                                                               |
| 33–34 | Deliverables and hostile-client acceptance                   | Development foundation implemented                        | Core hostile-client acceptance passes locally; operational production gates below remain open                                                                                                           |

## Verified commands

- `npm run check` and `npm run build`
- `npm run lint` (Prettier check)
- `npm test`: 8 passing; 2 external-service suites intentionally skipped in this command and executed separately
- `npm run test:integration`: 30 passing against real PostgreSQL/Redis
- `npm run test:failures`: 3 passing, including actual service stop/restart
- `npm run test:smoke`: reverse proxy → API → PostgreSQL → durable queue → real SMTP → verification/login, stopped/restarted worker, persisted session/workspace and API restart
- `npm audit --audit-level=high`: zero reported vulnerabilities at the latest check
- Docker image build and `docker compose --profile development up --wait`

## Outstanding production gates

- [ ] Connect the repository/registry and execute the CI/release workflows on the deployment infrastructure.
- [ ] Configure staging/production secrets, TLS ingress, trusted proxy CIDR, SMTP and outbound network rules.
- [ ] Exercise backup restoration and application-image rollback on staging with representative customer volumes.
- [ ] Run live webhook-provider and optional payment-provider acceptance.
- [ ] Expand notification-template, Enterprise and high-volume endpoint acceptance coverage.
- [ ] Add cursor pagination before tenants/history require browsing beyond the current 100-row response cap.
- [ ] Establish external metrics/log retention/alerts, load testing and capacity budgets.
- [ ] Complete an external security review and client operational acceptance.

No external environment has been deployed or represented as production ready. Local environment secrets are randomly generated and ignored by source control and Docker build context.
