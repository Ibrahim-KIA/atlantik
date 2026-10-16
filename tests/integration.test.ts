import { test } from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { Redis } from "ioredis";
import { randomUUID } from "node:crypto";
import { buildApp } from "../src/app.js";
import { pool, transaction, workerPool } from "../src/db.js";
import { decrypt, signature } from "../src/security.js";
import { hashPassword, digest, secret } from "../src/core.js";
import { processOne, scheduleTick, type Adapters } from "../src/jobs.js";
import { enqueue } from "../src/services.js";
const enabled = !!process.env.MIGRATION_DATABASE_URL;
test("real PostgreSQL / Redis acceptance", { skip: !enabled }, async (t) => {
  const admin = new pg.Pool({
    connectionString: process.env.MIGRATION_DATABASE_URL,
  });
  const redis = new Redis(process.env.REDIS_URL!);
  const app = await buildApp();
  let calls = 0;
  const request = async (
    method: string,
    url: string,
    payload?: unknown,
    token?: string,
    org?: string,
    extra: Record<string, string> = {},
  ) =>
    app.inject({
      method: method as any,
      url,
      payload: payload as any,
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(org ? { "x-organization-id": org } : {}),
        ...extra,
      },
      remoteAddress: `198.51.100.${(++calls % 200) + 1}`,
    });
  const expect = async (
    method: string,
    url: string,
    payload: unknown,
    token: string | undefined,
    org: string | undefined,
    status = 200,
  ) => {
    const r = await request(method, url, payload, token, org);
    assert.equal(r.statusCode, status, `${method} ${url}: ${r.body}`);
    return r.json();
  };
  const latestToken = async (email: string, kind = "verify") => {
    const rows = (
      await admin.query(
        "SELECT payload FROM outbox WHERE type='email' ORDER BY created_at DESC,id DESC",
      )
    ).rows;
    for (const row of rows) {
      if (!row.payload.encrypted) continue;
      const p = decrypt<any>(row.payload.encrypted);
      if (p.to === email && p.subject === `Atlantik ${kind}`)
        return p.text.split(": ").at(-1);
    }
    throw new Error("Token email not found");
  };
  async function account(label: string) {
    const email = `${label}-${randomUUID()}@example.test`;
    const a = await expect(
      "POST",
      "/api/v1/auth/register",
      {
        name: label,
        email,
        password: "secure password 123",
        organization: label,
        slug: `${label}-${randomUUID()}`,
      },
      undefined,
      undefined,
      201,
    );
    const token = await latestToken(email);
    await expect(
      "POST",
      "/api/v1/auth/verify",
      { token },
      undefined,
      undefined,
    );
    const login = await expect(
      "POST",
      "/api/v1/auth/login",
      { email, password: "secure password 123" },
      undefined,
      undefined,
    );
    return { ...a, email, token: login.token, verifyToken: token };
  }
  try {
    assert.ok(
      new URL(process.env.MIGRATION_DATABASE_URL!).pathname.endsWith("_test"),
      "Integration requires an isolated database ending _test",
    );
    await admin.query(
      "TRUNCATE users,organizations,outbox,platform_audit,schedule_runs CASCADE",
    );
    await redis.flushdb();
    const a = await account("alpha");
    const b = await account("bravo");
    let workspace: string;
    let key: any;
    let member: any;
    await t.test("readiness succeeds with real dependencies", async () => {
      const r = await app.inject("/health/ready");
      assert.equal(r.statusCode, 200, r.body);
    });
    await t.test("verification tokens cannot replay", async () => {
      await expect(
        "POST",
        "/api/v1/auth/verify",
        { token: a.verifyToken },
        undefined,
        undefined,
        400,
      );
    });
    await t.test("cross-tenant reads and guessed IDs denied", async () => {
      const w = await expect(
        "POST",
        "/api/v1/workspaces",
        { name: "private alpha" },
        a.token,
        a.organizationId,
      );
      workspace = w.id;
      await expect(
        "GET",
        `/api/v1/workspaces/${workspace}`,
        undefined,
        b.token,
        b.organizationId,
        404,
      );
      await expect(
        "GET",
        `/api/v1/workspaces/${workspace}`,
        undefined,
        b.token,
        a.organizationId,
        401,
      );
      await expect(
        "PATCH",
        `/api/v1/users/${a.userId}/role`,
        { role: "member" },
        b.token,
        b.organizationId,
        404,
      );
    });
    await t.test("forced database RLS hides foreign tenant rows", async () => {
      await transaction(b.organizationId, async (db) => {
        const rows = await db.query("SELECT * FROM workspaces WHERE id=$1", [
          workspace,
        ]);
        assert.equal(rows.rowCount, 0);
        assert.equal(
          (
            await db.query(
              "SELECT id,settings FROM organizations WHERE id=$1",
              [a.organizationId],
            )
          ).rowCount,
          0,
        );
        await assert.rejects(
          db.query("INSERT INTO workspaces(org_id,name) VALUES($1,$2)", [
            a.organizationId,
            "attack",
          ]),
          /row-level security/,
        );
      });
    });
    await t.test("owner cannot be demoted by role assignment", async () => {
      await expect(
        "PATCH",
        `/api/v1/users/${a.userId}/role`,
        { role: "member" },
        a.token,
        a.organizationId,
        404,
      );
    });
    await t.test(
      "scoped key cannot create or administer, cross-tenant key fails",
      async () => {
        key = await expect(
          "POST",
          "/api/v1/api-keys",
          {
            name: "ci",
            scopes: ["workspaces.read"],
            expiresAt: new Date(Date.now() + 3600000).toISOString(),
          },
          a.token,
          a.organizationId,
        );
        await expect(
          "POST",
          "/api/v1/workspaces",
          { name: "attack" },
          key.secret,
          a.organizationId,
          403,
        );
        await expect(
          "GET",
          "/api/v1/api-keys",
          undefined,
          key.secret,
          a.organizationId,
          403,
        );
        await expect(
          "GET",
          "/api/v1/workspaces",
          undefined,
          key.secret,
          b.organizationId,
          401,
        );
        const keys = await expect(
          "GET",
          "/api/v1/api-keys",
          undefined,
          a.token,
          a.organizationId,
        );
        assert.ok(!JSON.stringify(keys).includes(key.secret));
      },
    );
    await t.test(
      "rotation invalidates old key and revoked/expired keys fail",
      async () => {
        const rotated = await expect(
          "POST",
          `/api/v1/api-keys/${key.id}/rotate`,
          {},
          a.token,
          a.organizationId,
        );
        await expect(
          "GET",
          "/api/v1/workspaces",
          undefined,
          key.secret,
          a.organizationId,
          401,
        );
        await expect(
          "GET",
          "/api/v1/workspaces",
          undefined,
          rotated.secret,
          a.organizationId,
        );
        await admin.query(
          "UPDATE api_keys SET expires_at=now()-interval '1 second' WHERE id=$1",
          [key.id],
        );
        await expect(
          "GET",
          "/api/v1/workspaces",
          undefined,
          rotated.secret,
          a.organizationId,
          401,
        );
        await expect(
          "DELETE",
          `/api/v1/api-keys/${key.id}`,
          undefined,
          a.token,
          a.organizationId,
        );
      },
    );
    await t.test(
      "workspace quotas remain correct under concurrency",
      async () => {
        const results = await Promise.all(
          Array.from({ length: 4 }, (_, i) =>
            request(
              "POST",
              "/api/v1/workspaces",
              { name: `concurrent-${i}` },
              a.token,
              a.organizationId,
            ),
          ),
        );
        assert.equal(results.filter((r) => r.statusCode === 200).length, 2);
        assert.equal(results.filter((r) => r.statusCode === 409).length, 2);
      },
    );
    await t.test(
      "invitation address binding, acceptance, team ACL and privilege boundaries",
      async () => {
        member = await account("member");
        const inv = await expect(
          "POST",
          "/api/v1/invitations",
          { email: member.email },
          a.token,
          a.organizationId,
        );
        const rows = (
          await admin.query(
            "SELECT payload FROM outbox WHERE org_id=$1 AND type='email' ORDER BY created_at DESC",
            [a.organizationId],
          )
        ).rows;
        const msg = rows
          .map((r) => decrypt<any>(r.payload.encrypted))
          .find(
            (p) => p.subject === "Atlantik invitation" && p.to === member.email,
          );
        const token = msg.text.split(": ").at(-1);
        await expect(
          "POST",
          "/api/v1/invitations/accept",
          { organizationId: a.organizationId, token },
          b.token,
          undefined,
          400,
        );
        await expect(
          "POST",
          "/api/v1/invitations/accept",
          { organizationId: a.organizationId, token },
          member.token,
          undefined,
        );
        await expect(
          "POST",
          "/api/v1/invitations/accept",
          { organizationId: a.organizationId, token },
          member.token,
          undefined,
          400,
        );
        await expect(
          "GET",
          `/api/v1/workspaces/${workspace}`,
          undefined,
          member.token,
          a.organizationId,
          404,
        );
        await expect(
          "POST",
          "/api/v1/teams",
          { name: "escalate" },
          member.token,
          a.organizationId,
          403,
        );
        const team = await expect(
          "POST",
          "/api/v1/teams",
          { name: "engineering" },
          a.token,
          a.organizationId,
        );
        await expect(
          "PUT",
          `/api/v1/teams/${team.id}/members/${member.userId}`,
          undefined,
          a.token,
          a.organizationId,
        );
        await expect(
          "PUT",
          `/api/v1/workspaces/${workspace}/teams/${team.id}`,
          undefined,
          a.token,
          a.organizationId,
        );
        await expect(
          "GET",
          `/api/v1/workspaces/${workspace}`,
          undefined,
          member.token,
          a.organizationId,
        );
        await expect(
          "PUT",
          `/api/v1/teams/${team.id}/members/${b.userId}`,
          undefined,
          a.token,
          a.organizationId,
          409,
        );
        await expect(
          "PATCH",
          `/api/v1/users/${member.userId}/role`,
          { role: "admin" },
          a.token,
          a.organizationId,
        );
        await expect(
          "PATCH",
          "/api/v1/subscription",
          { plan: "pro", status: "ACTIVE" },
          member.token,
          a.organizationId,
          403,
        );
        await expect(
          "DELETE",
          "/api/v1/organization",
          undefined,
          member.token,
          a.organizationId,
          403,
        );
        await expect(
          "PATCH",
          `/api/v1/users/${member.userId}/role`,
          { role: "member" },
          a.token,
          a.organizationId,
        );
      },
    );
    await t.test(
      "custom roles evaluated dynamically without owner privilege grants",
      async () => {
        await expect(
          "POST",
          "/api/v1/roles",
          { name: "bad", permissions: ["billing.manage"] },
          a.token,
          a.organizationId,
          403,
        );
        const role = await expect(
          "POST",
          "/api/v1/roles",
          {
            name: "team-reader",
            permissions: ["teams.read", "workspaces.read"],
          },
          a.token,
          a.organizationId,
        );
        await expect(
          "PUT",
          `/api/v1/users/${member.userId}/custom-role`,
          { roleId: role.id },
          a.token,
          a.organizationId,
        );
        await expect(
          "GET",
          "/api/v1/teams",
          undefined,
          member.token,
          a.organizationId,
        );
        await expect(
          "POST",
          "/api/v1/teams",
          { name: "escalate" },
          member.token,
          a.organizationId,
          403,
        );
        await expect(
          "PATCH",
          `/api/v1/roles/${role.id}`,
          { permissions: [] },
          a.token,
          a.organizationId,
        );
        await expect(
          "GET",
          "/api/v1/teams",
          undefined,
          member.token,
          a.organizationId,
          403,
        );
        await expect(
          "PATCH",
          `/api/v1/roles/${role.id}`,
          { permissions: ["teams.read", "workspaces.read"] },
          a.token,
          a.organizationId,
        );
        await expect(
          "GET",
          "/api/v1/teams",
          undefined,
          member.token,
          a.organizationId,
        );
        await expect(
          "DELETE",
          `/api/v1/roles/${role.id}`,
          undefined,
          a.token,
          a.organizationId,
          409,
        );
      },
    );
    await t.test("idempotent usage events do not double charge", async () => {
      const first = await expect(
        "POST",
        "/api/v1/usage/events",
        { eventId: "same", metric: "storage", quantity: 100 },
        a.token,
        a.organizationId,
      );
      const second = await expect(
        "POST",
        "/api/v1/usage/events",
        { eventId: "same", metric: "storage", quantity: 100 },
        a.token,
        a.organizationId,
      );
      assert.equal(second.duplicate, true);
      assert.equal(first.quantity, 100);
    });
    await t.test(
      "storage quota, releases, and failed-event rollback",
      async () => {
        await expect(
          "POST",
          "/api/v1/usage/events",
          { eventId: "storage-over", metric: "storage", quantity: 1073741824 },
          a.token,
          a.organizationId,
          429,
        );
        const released = await expect(
          "POST",
          "/api/v1/usage/events",
          { eventId: "storage-release", metric: "storage", quantity: -25 },
          a.token,
          a.organizationId,
        );
        assert.equal(released.quantity, 75);
        await expect(
          "POST",
          "/api/v1/usage/events",
          {
            eventId: "storage-release-too-much",
            metric: "storage",
            quantity: -1000,
          },
          a.token,
          a.organizationId,
          400,
        );
        assert.equal(
          (
            await admin.query(
              "SELECT count(*) FROM usage_events WHERE org_id=$1 AND id='storage-over'",
              [a.organizationId],
            )
          ).rows[0].count,
          "0",
        );
      },
    );
    await t.test(
      "request quota cannot block billing recovery and denials are audited",
      async () => {
        await admin.query(
          "UPDATE usage SET quantity=9999 WHERE org_id=$1 AND metric='requests'",
          [a.organizationId],
        );
        await expect(
          "GET",
          "/api/v1/organization",
          undefined,
          a.token,
          a.organizationId,
        );
        const denied = await expect(
          "GET",
          "/api/v1/organization",
          undefined,
          a.token,
          a.organizationId,
          429,
        );
        await expect(
          "GET",
          "/api/v1/subscription",
          undefined,
          a.token,
          a.organizationId,
        );
        assert.equal(
          (
            await admin.query(
              "SELECT result FROM audit_logs WHERE request_id=$1",
              [denied.requestId],
            )
          ).rows[0].result,
          "failure",
        );
        await admin.query(
          "UPDATE usage SET quantity=1 WHERE org_id=$1 AND metric='requests'",
          [a.organizationId],
        );
      },
    );
    await t.test(
      "organization listing and password-confirmed ownership transfer",
      async () => {
        await admin.query("UPDATE users SET platform_admin=true WHERE id=$1", [
          b.userId,
        ]);
        const own = await expect(
          "GET",
          "/api/v1/organizations",
          undefined,
          a.token,
          undefined,
        );
        assert.ok(own.some((o: any) => o.id === a.organizationId));
        assert.ok(!own.some((o: any) => o.id === b.organizationId));
        const o = await expect(
          "POST",
          "/api/v1/organizations",
          { name: "Transfer", slug: `transfer-${randomUUID()}` },
          a.token,
          undefined,
        );
        await expect(
          "POST",
          "/api/v1/invitations",
          { email: b.email },
          a.token,
          o.id,
        );
        const rows = (
          await admin.query(
            "SELECT payload FROM outbox WHERE org_id=$1 AND type='email' ORDER BY created_at DESC",
            [o.id],
          )
        ).rows;
        const msg = rows
          .map((r) => decrypt<any>(r.payload.encrypted))
          .find((p) => p.subject === "Atlantik invitation");
        await expect(
          "POST",
          "/api/v1/invitations/accept",
          { organizationId: o.id, token: msg.text.split(": ").at(-1) },
          b.token,
          undefined,
        );
        await expect(
          "POST",
          "/api/v1/organization/transfer",
          { userId: b.userId, password: "wrong" },
          a.token,
          o.id,
          401,
        );
        await expect(
          "POST",
          "/api/v1/organization/transfer",
          { userId: b.userId, password: "secure password 123" },
          a.token,
          o.id,
        );
        await expect(
          "PATCH",
          "/api/v1/subscription",
          { plan: "pro", status: "ACTIVE" },
          a.token,
          o.id,
          403,
        );
        await expect(
          "PATCH",
          "/api/v1/subscription",
          { plan: "pro", status: "ACTIVE" },
          b.token,
          o.id,
        );
        await expect(
          "PATCH",
          `/api/v1/platform/organizations/${o.id}/status`,
          { status: "SUSPENDED" },
          b.token,
          undefined,
        );
        await expect(
          "GET",
          "/api/v1/workspaces",
          undefined,
          b.token,
          o.id,
          403,
        );
        await expect(
          "PATCH",
          `/api/v1/platform/organizations/${o.id}/status`,
          { status: "ACTIVE" },
          b.token,
          undefined,
        );
        await expect("GET", "/api/v1/workspaces", undefined, b.token, o.id);
      },
    );
    await t.test(
      "API role cannot read queued secrets or bypass row security",
      async () => {
        await assert.rejects(
          pool.query("SELECT payload FROM outbox LIMIT 1"),
          /permission denied/,
        );
        const role = (
          await pool.query(
            "SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user",
          )
        ).rows[0];
        assert.equal(role.rolsuper, false);
        await assert.rejects(
          pool.query("UPDATE users SET platform_admin=true WHERE id=$1", [
            a.userId,
          ]),
          /permission denied/,
        );
        assert.equal(role.rolbypassrls, false);
      },
    );
    await t.test(
      "expired sessions and suspended tenants fail closed",
      async () => {
        const token = secret();
        await admin.query(
          "INSERT INTO sessions(user_id,digest,expires_at) VALUES($1,$2,now()-interval '1 second')",
          [a.userId, digest(token)],
        );
        await expect(
          "GET",
          "/api/v1/organization",
          undefined,
          token,
          a.organizationId,
          401,
        );
        await admin.query(
          "UPDATE organizations SET status='SUSPENDED' WHERE id=$1",
          [a.organizationId],
        );
        await expect(
          "GET",
          "/api/v1/workspaces",
          undefined,
          a.token,
          a.organizationId,
          403,
        );
        await admin.query(
          "UPDATE organizations SET status='ACTIVE' WHERE id=$1",
          [a.organizationId],
        );
      },
    );
    await t.test("audit rows cannot be rewritten by application", async () => {
      await assert.rejects(
        transaction(a.organizationId, async (db) => {
          await db.query(
            "UPDATE audit_logs SET event='tampered' WHERE org_id=$1",
            [a.organizationId],
          );
        }),
        /permission denied|append only/,
      );
    });
    await t.test(
      "platform privileges do not imply tenant membership",
      async () => {
        await admin.query("UPDATE users SET platform_admin=true WHERE id=$1", [
          b.userId,
        ]);
        await expect(
          "GET",
          "/api/v1/platform/organizations",
          undefined,
          b.token,
          undefined,
        );
        await expect(
          "GET",
          "/api/v1/workspaces",
          undefined,
          b.token,
          a.organizationId,
          401,
        );
        await expect(
          "GET",
          "/api/v1/platform/organizations",
          undefined,
          a.token,
          undefined,
          403,
        );
      },
    );
    await t.test(
      "billing signatures reject replay window; duplicate events apply once",
      async () => {
        const payload = JSON.stringify({
          id: `billing-${randomUUID()}`,
          organizationId: a.organizationId,
          type: "payment.failed",
          version: 1,
        });
        const ts = String(Math.floor(Date.now() / 1000));
        const headers = {
          "content-type": "application/json",
          "x-atlantik-timestamp": ts,
          "x-atlantik-signature": signature(
            process.env.BILLING_WEBHOOK_SECRET!,
            ts,
            payload,
          ),
        };
        const r = await request(
          "POST",
          "/api/v1/billing/events",
          payload,
          undefined,
          undefined,
          headers,
        );
        assert.equal(r.statusCode, 200, r.body);
        const d = await request(
          "POST",
          "/api/v1/billing/events",
          payload,
          undefined,
          undefined,
          headers,
        );
        assert.equal(d.json().duplicate, true);
        await request(
          "POST",
          "/api/v1/billing/events",
          payload,
          undefined,
          undefined,
          { ...headers, "x-atlantik-timestamp": "1" },
        ).then((r) => assert.equal(r.statusCode, 401));
        await admin.query(
          "UPDATE outbox SET available_at=now()-interval '1 hour' WHERE type='billing'",
        );
        const io: Adapters = { mail: async () => {}, webhook: async () => 200 };
        await processOne(io);
        const org = (
          await admin.query(
            "SELECT subscription_version,subscription_status FROM organizations WHERE id=$1",
            [a.organizationId],
          )
        ).rows[0];
        assert.equal(Number(org.subscription_version), 1);
        assert.equal(org.subscription_status, "PAST_DUE");
      },
    );
    await t.test(
      "webhook SSRF rejected and delivery retries preserve event ID",
      async () => {
        await expect(
          "POST",
          "/api/v1/webhooks",
          { url: "http://127.0.0.1/private" },
          a.token,
          a.organizationId,
          400,
        );
        const w = await expect(
          "POST",
          "/api/v1/webhooks",
          { url: "https://example.com/hook" },
          a.token,
          a.organizationId,
        );
        await transaction(a.organizationId, (db) =>
          enqueue(db, a.organizationId, "event", {
            type: "test",
            data: { safe: true },
          }),
        );
        await admin.query(
          "UPDATE outbox SET available_at=now()-interval '2 hours' WHERE type='event' AND completed_at IS NULL",
        );
        const io: Adapters = {
          mail: async () => {},
          webhook: async () => {
            throw new Error("Timeout");
          },
        };
        for (let i = 0; i < 10; i++) await processOne(io);
        const deliveries = (
          await admin.query(
            "SELECT * FROM webhook_deliveries WHERE org_id=$1 AND webhook_id=$2",
            [a.organizationId, w.id],
          )
        ).rows;
        assert.ok(deliveries.length > 0);
        await admin.query(
          "UPDATE outbox SET available_at=now()-interval '3 hours' WHERE type='webhook' AND completed_at IS NULL",
        );
        await processOne(io);
        const retried = (
          await admin.query(
            "SELECT * FROM webhook_deliveries WHERE org_id=$1 AND attempts>0",
            [a.organizationId],
          )
        ).rows;
        assert.ok(retried.length > 0);
        let eventId: string | undefined;
        const ok: Adapters = {
          mail: async () => {},
          webhook: async (_url, body, h) => {
            assert.equal(JSON.parse(body).id, h["x-atlantik-event-id"]);
            eventId = h["x-atlantik-event-id"];
            return 204;
          },
        };
        await admin.query(
          "UPDATE outbox SET available_at=now()-interval '3 hours' WHERE type='webhook' AND completed_at IS NULL",
        );
        await processOne(ok);
        assert.ok(eventId);
      },
    );
    await t.test(
      "email failure retains encrypted job and retry succeeds",
      async () => {
        await transaction(undefined, (db) =>
          enqueue(db, null, "email", {
            to: "test@example.test",
            subject: "test",
            text: "private",
          }),
        );
        await admin.query(
          "UPDATE outbox SET available_at=now()-interval '4 hours' WHERE type='email' AND completed_at IS NULL",
        );
        await processOne({
          mail: async () => {
            throw new Error("SMTP down");
          },
          webhook: async () => 200,
        });
        assert.ok(
          (
            await admin.query(
              "SELECT 1 FROM outbox WHERE type='email' AND attempts>0 AND completed_at IS NULL",
            )
          ).rowCount,
        );
        await admin.query(
          "UPDATE outbox SET available_at=now()-interval '4 hours' WHERE type='email' AND completed_at IS NULL",
        );
        await processOne({ mail: async () => {}, webhook: async () => 200 });
        assert.ok(
          (
            await admin.query(
              "SELECT 1 FROM outbox WHERE type='email' AND completed_at IS NOT NULL AND payload='{}'::jsonb",
            )
          ).rowCount,
        );
      },
    );
    await t.test(
      "stale billing events cannot regress a newer subscription",
      async () => {
        await transaction(a.organizationId, (db) =>
          enqueue(db, a.organizationId, "billing", {
            id: "newest",
            type: "payment.succeeded",
            version: 3,
          }),
        );
        await admin.query(
          "UPDATE outbox SET available_at=now()-interval '12 hours' WHERE type='billing' AND completed_at IS NULL",
        );
        await processOne({ mail: async () => {}, webhook: async () => 200 });
        await transaction(a.organizationId, (db) =>
          enqueue(db, a.organizationId, "billing", {
            id: "old",
            type: "payment.failed",
            version: 2,
          }),
        );
        await admin.query(
          "UPDATE outbox SET available_at=now()-interval '12 hours' WHERE type='billing' AND completed_at IS NULL",
        );
        await processOne({ mail: async () => {}, webhook: async () => 200 });
        const o = (
          await admin.query(
            "SELECT subscription_version,subscription_status FROM organizations WHERE id=$1",
            [a.organizationId],
          )
        ).rows[0];
        assert.equal(Number(o.subscription_version), 3);
        assert.equal(o.subscription_status, "ACTIVE");
      },
    );
    await t.test(
      "worker connection crash releases job lock without losing work",
      async () => {
        await transaction(undefined, (db) =>
          enqueue(db, null, "email", {
            to: "crash@example.test",
            subject: "crash-test",
            text: "safe",
          }),
        );
        const job = (
          await admin.query(
            "SELECT id FROM outbox WHERE type='email' AND completed_at IS NULL ORDER BY created_at DESC LIMIT 1",
          )
        ).rows[0];
        await admin.query(
          "UPDATE outbox SET available_at=now()-interval '14 hours' WHERE id=$1",
          [job.id],
        );
        const crashed = new pg.Client({
          connectionString: process.env.WORKER_DATABASE_URL,
        });
        crashed.on("error", () => {});
        await crashed.connect();
        await crashed.query("BEGIN");
        await crashed.query("SELECT id FROM outbox WHERE id=$1 FOR UPDATE", [
          job.id,
        ]);
        const pid = (await crashed.query("SELECT pg_backend_pid() AS pid"))
          .rows[0].pid;
        await admin.query("SELECT pg_terminate_backend($1)", [pid]);
        await new Promise((r) => setTimeout(r, 50));
        let delivered = false;
        await processOne({
          mail: async (_p, id) => {
            if (id === job.id) delivered = true;
          },
          webhook: async () => 200,
        });
        assert.ok(delivered);
        await crashed.end().catch(() => {});
      },
    );
    await t.test("jobs stop retrying after eight failures", async () => {
      await transaction(undefined, (db) =>
        enqueue(db, null, "email", {
          to: "dead@example.test",
          subject: "dead-test",
          text: "safe",
        }),
      );
      const job = (
        await admin.query(
          "SELECT id FROM outbox WHERE type='email' AND completed_at IS NULL ORDER BY created_at DESC LIMIT 1",
        )
      ).rows[0];
      for (let i = 0; i < 8; i++) {
        await admin.query(
          "UPDATE outbox SET available_at=now()-interval '16 hours' WHERE id=$1",
          [job.id],
        );
        await processOne({
          mail: async () => {
            throw new Error("Dependency down");
          },
          webhook: async () => 200,
        });
      }
      const dead = (
        await admin.query(
          "SELECT attempts,completed_at FROM outbox WHERE id=$1",
          [job.id],
        )
      ).rows[0];
      assert.equal(dead.attempts, 8);
      assert.equal(dead.completed_at, null);
    });
    await t.test(
      "expired reset/verification tokens and suspended users are rejected",
      async () => {
        for (const kind of ["verify", "reset"]) {
          const token = secret();
          await admin.query(
            "INSERT INTO tokens(user_id,kind,digest,expires_at) VALUES($1,$2,$3,now()-interval '1 second')",
            [a.userId, kind, digest(token)],
          );
          await expect(
            "POST",
            kind === "verify"
              ? "/api/v1/auth/verify"
              : "/api/v1/auth/password-reset/confirm",
            kind === "verify"
              ? { token }
              : { token, password: "unused safe password" },
            undefined,
            undefined,
            400,
          );
        }
        await admin.query("UPDATE users SET status='SUSPENDED' WHERE id=$1", [
          b.userId,
        ]);
        await expect("GET", "/api/v1/me", undefined, b.token, undefined, 401);
        await expect(
          "POST",
          "/api/v1/auth/login",
          { email: b.email, password: "secure password 123" },
          undefined,
          undefined,
          401,
        );
        await admin.query("UPDATE users SET status='ACTIVE' WHERE id=$1", [
          b.userId,
        ]);
      },
    );
    await t.test(
      "profile, password/email changes, verification, tombstone and tenant-independent logout",
      async () => {
        const u = await account("profile");
        await expect(
          "PATCH",
          "/api/v1/me",
          { name: "bad", platform_admin: true },
          u.token,
          undefined,
          400,
        );
        const injection = "Renamed'); DROP TABLE users;--";
        await expect(
          "PATCH",
          "/api/v1/me",
          { name: injection },
          u.token,
          undefined,
        );
        assert.equal(
          (await expect("GET", "/api/v1/me", undefined, u.token, undefined))
            .name,
          injection,
        );

        await expect(
          "PATCH",
          "/api/v1/me",
          { name: "Renamed" },
          u.token,
          undefined,
        );
        assert.equal(
          (await expect("GET", "/api/v1/me", undefined, u.token, undefined))
            .name,
          "Renamed",
        );
        await expect(
          "POST",
          "/api/v1/auth/password/change",
          {
            currentPassword: "secure password 123",
            password: "replacement safe password",
          },
          u.token,
          undefined,
        );
        await expect("GET", "/api/v1/me", undefined, u.token, undefined, 401);
        const login = await expect(
          "POST",
          "/api/v1/auth/login",
          { email: u.email, password: "replacement safe password" },
          undefined,
          undefined,
        );
        const email = `changed-${randomUUID()}@example.test`;
        await expect(
          "POST",
          "/api/v1/auth/email/change",
          { email, password: "replacement safe password" },
          login.token,
          undefined,
        );
        await expect(
          "GET",
          "/api/v1/me",
          undefined,
          login.token,
          undefined,
          401,
        );
        await expect(
          "POST",
          "/api/v1/auth/login",
          { email, password: "replacement safe password" },
          undefined,
          undefined,
          401,
        );
        await expect(
          "POST",
          "/api/v1/auth/verify",
          { token: await latestToken(email) },
          undefined,
          undefined,
        );
        const verified = await expect(
          "POST",
          "/api/v1/auth/login",
          { email, password: "replacement safe password" },
          undefined,
          undefined,
        );
        await expect(
          "DELETE",
          "/api/v1/organization",
          undefined,
          verified.token,
          u.organizationId,
        );
        await expect(
          "GET",
          "/api/v1/organization",
          undefined,
          verified.token,
          u.organizationId,
          403,
        );
        await expect(
          "POST",
          "/api/v1/auth/logout",
          {},
          verified.token,
          undefined,
        );
        await expect(
          "GET",
          "/api/v1/me",
          undefined,
          verified.token,
          undefined,
          401,
        );
      },
    );
    await t.test(
      "schedules are restart-safe and expired trials suspended",
      async () => {
        await admin.query(
          "UPDATE organizations SET subscription_status='TRIAL',renewal_at=now()-interval '1 hour' WHERE id=$1",
          [a.organizationId],
        );
        await scheduleTick();
        await scheduleTick();
        assert.equal(
          (
            await admin.query(
              "SELECT subscription_status FROM organizations WHERE id=$1",
              [a.organizationId],
            )
          ).rows[0].subscription_status,
          "SUSPENDED",
        );
        assert.equal(
          (
            await admin.query(
              "SELECT count(*) FROM schedule_runs WHERE name=$1",
              [`report:${a.organizationId}`],
            )
          ).rows[0].count,
          "1",
        );
      },
    );
    await t.test(
      "non-owner password reset works and invalidates existing sessions",
      async () => {
        await expect(
          "POST",
          "/api/v1/auth/password-reset/request",
          { email: member.email },
          undefined,
          undefined,
        );
        const token = await latestToken(member.email, "reset");
        await expect(
          "POST",
          "/api/v1/auth/password-reset/confirm",
          { token, password: "a new safe password" },
          undefined,
          undefined,
        );
        await expect(
          "GET",
          "/api/v1/me",
          undefined,
          member.token,
          undefined,
          401,
        );
        await expect(
          "POST",
          "/api/v1/auth/password-reset/confirm",
          { token, password: "another safe password" },
          undefined,
          undefined,
          400,
        );
      },
    );
    await t.test("distributed login rate limit enforced", async () => {
      let last;
      for (let i = 0; i < 11; i++)
        last = await app.inject({
          method: "POST",
          url: "/api/v1/auth/login",
          payload: { email: a.email, password: "bad" },
          remoteAddress: "203.0.113.250",
        });
      assert.equal(last!.statusCode, 429);
    });
  } finally {
    await app.close();
    await redis.quit();
    await pool.end();
    await workerPool.end();
    await admin.end();
  }
});
