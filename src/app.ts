import Fastify, { type FastifyRequest } from "fastify";
import { readFile } from "node:fs/promises";
import helmet from "@fastify/helmet";
import { Redis } from "ioredis";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import {
  enqueue,
  event,
  notify,
  meter,
  limits,
  audit,
  type Context,
} from "./services.js";
import { featureRoutes } from "./features.js";
import type pg from "pg";
import { pool, transaction } from "./db.js";
import {
  ApiError,
  digest,
  secret,
  hashPassword,
  verifyPassword,
  permissions,
  plans,
  requirePermission,
} from "./core.js";
const dummyHash = await hashPassword("noncredential timing equalizer");
const uuid = z.string().uuid();
const password = z.string().min(12).max(128);
const redis = new Redis(process.env.REDIS_URL ?? "redis://localhost:6379", {
  lazyConnect: true,
  maxRetriesPerRequest: 1,
  enableOfflineQueue: false,
});
redis.on("error", () => {});
export async function buildApp() {
  const metrics = new Map<
    string,
    { count: number; totalMs: number; errors: number }
  >();
  const app = Fastify({
    trustProxy: process.env.TRUST_PROXY || false,
    genReqId: () => randomUUID(),
    bodyLimit: 65536,
    logger: {
      serializers: {
        req: (req: any) => ({
          method: req.method,
          url: req.url?.split("?")[0],
          remoteAddress: req.ip,
        }),
      },
      redact: [
        "req.headers.authorization",
        "req.headers.cookie",
        "password",
        "token",
        "secret",
      ],
    },
  });
  await app.register(helmet);
  app.addHook("onResponse", async (req, reply) => {
    const key = `${req.method} ${req.routeOptions.url ?? "unmatched"}`;
    const value = metrics.get(key) ?? { count: 0, totalMs: 0, errors: 0 };
    value.count++;
    value.totalMs += reply.elapsedTime;
    if (reply.statusCode >= 500) value.errors++;
    metrics.set(key, value);
  });
  app.addHook("onRequest", async (req) => {
    if (
      req.url.startsWith("/api/") &&
      !req.url.startsWith("/api/v1/platform/") &&
      !req.url.startsWith("/api/v1/auth/")
    ) {
      const config = await pool.query(
        "SELECT value FROM platform_config WHERE key='maintenance'",
      );
      if (config.rows[0]?.value === true)
        throw new ApiError(
          503,
          "MAINTENANCE",
          "Platform maintenance in progress",
        );
    }
  });
  app.addHook("onRequest", async (req, reply) => {
    reply.header("x-request-id", req.id);
  });
  app.setErrorHandler(async (error, req, reply) => {
    reply.header("x-request-id", req.id);
    if (
      req.url.startsWith("/api/v1/auth/") &&
      error instanceof ApiError &&
      [401, 429].includes(error.status)
    ) {
      try {
        await pool.query(
          "INSERT INTO platform_audit(event,request_id,ip,result) VALUES($1,$2,$3,'failure')",
          [req.routeOptions.url ?? "auth.failure", req.id, req.ip],
        );
      } catch {
        req.log.error("Authentication audit unavailable");
      }
    }
    if (error instanceof z.ZodError)
      return reply.code(400).send({
        code: "INVALID_INPUT",
        message: "Invalid request",
        details: error.issues.map((x) => ({
          path: x.path,
          message: x.message,
        })),
        requestId: req.id,
      });
    const e =
      error instanceof ApiError
        ? error
        : (error as any).code === "23505"
          ? new ApiError(409, "CONFLICT", "Resource already exists")
          : (error as any).code === "23503"
            ? new ApiError(
                409,
                "INVALID_REFERENCE",
                "Referenced resource unavailable",
              )
            : [400, 413, 415].includes((error as any).statusCode)
              ? new ApiError(
                  (error as any).statusCode,
                  "INVALID_INPUT",
                  "Invalid request body",
                )
              : new ApiError(503, "SERVICE_UNAVAILABLE", "Service unavailable");
    if (!(error instanceof ApiError))
      req.log.error(
        { err: { name: error instanceof Error ? error.name : "UnknownError" } },
        "Dependency or internal failure",
      );
    reply.code(e.status).send({
      code: e.code,
      message: e.message,
      details: [],
      requestId: req.id,
    });
  });
  app.setNotFoundHandler((req, reply) =>
    reply.code(404).send({
      code: "NOT_FOUND",
      message: "Endpoint not found",
      details: [],
      requestId: req.id,
    }),
  );
  app.get("/openapi.json", async () =>
    JSON.parse(await readFile("docs/openapi.json", "utf8")),
  );
  app.get("/health/live", async () => ({
    status: "alive",
    service: "Atlantik",
  }));
  app.get("/health/ready", async () => {
    await pool.query("SELECT 1");
    if (redis.status === "wait") await redis.connect();
    await redis.ping();
    return { status: "ready" };
  });
  async function rate(key: string, limit: number) {
    if (redis.status === "wait") await redis.connect();
    const count = await redis.eval(
      "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],60) end; return n",
      1,
      `atlantik:rate:${key}`,
    );
    if (Number(count) > limit)
      throw new ApiError(429, "RATE_LIMIT", "Too many requests");
  }
  async function emit(
    db: pg.PoolClient,
    org: string | null,
    type: string,
    payload: unknown,
  ) {
    if (type === "email") await enqueue(db, org, type, payload);
    else if (org) await event(db, org, type, payload);
  }
  async function issue(
    db: pg.PoolClient,
    user: string,
    email: string,
    kind: string,
    org: string | null,
  ) {
    await db.query("SELECT id FROM users WHERE id=$1 FOR UPDATE", [user]);
    const token = secret();
    await db.query("DELETE FROM tokens WHERE user_id=$1 AND kind=$2", [
      user,
      kind,
    ]);
    await db.query(
      "INSERT INTO tokens(user_id,kind,digest,expires_at) VALUES($1,$2,$3,now()+interval '1 hour')",
      [user, kind, digest(token)],
    );
    await emit(db, org, "email", {
      to: email,
      subject: `Atlantik ${kind}`,
      text: `Your one-time ${kind} token: ${token}`,
    });
  }
  app.post("/api/v1/auth/register", async (req, reply) => {
    await rate(`register:${req.ip}`, 5);
    const b = z
      .object({
        name: z.string().min(1).max(100),
        email: z.email().max(254),
        password,
        organization: z.string().min(1).max(100),
        slug: z.string().regex(/^[a-z0-9-]{3,60}$/),
      })
      .strict()
      .parse(req.body);
    const result = await transaction(undefined, async (db) => {
      if (
        (
          await db.query(
            "SELECT value FROM platform_config WHERE key='signupEnabled'",
          )
        ).rows[0]?.value === false
      )
        throw new ApiError(403, "SIGNUP_DISABLED", "Registration is disabled");
      const u = (
        await db.query(
          "INSERT INTO users(name,email,password) VALUES($1,$2,$3) ON CONFLICT(email) DO NOTHING RETURNING id",
          [b.name, b.email.toLowerCase(), await hashPassword(b.password)],
        )
      ).rows[0];
      if (!u)
        throw new ApiError(
          409,
          "ACCOUNT_EXISTS",
          "Account could not be created",
        );
      const orgId = randomUUID();
      await db.query("SELECT set_config('app.org_id',$1,true)", [orgId]);
      const o = (
        await db.query(
          "INSERT INTO organizations(id,name,slug,owner_id) VALUES($1,$2,$3,$4) RETURNING id",
          [orgId, b.organization, b.slug, u.id],
        )
      ).rows[0];
      await db.query(
        "INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')",
        [o.id, u.id],
      );
      await issue(db, u.id, b.email, "verify", o.id);
      return { userId: u.id, organizationId: o.id };
    });
    return reply.code(201).send(result);
  });
  app.post("/api/v1/auth/verify", async (req) => {
    await rate(`verify:${req.ip}`, 10);
    const b = z
      .object({ token: z.string().min(20).max(200) })
      .strict()
      .parse(req.body);
    return transaction(undefined, async (db) => {
      const t = (
        await db.query(
          "DELETE FROM tokens WHERE digest=$1 AND kind='verify' AND expires_at>now() RETURNING user_id",
          [digest(b.token)],
        )
      ).rows[0];
      if (!t)
        throw new ApiError(400, "INVALID_TOKEN", "Token invalid or expired");
      await db.query(
        "UPDATE users SET status='ACTIVE' WHERE id=$1 AND status='PENDING_VERIFICATION'",
        [t.user_id],
      );
      return { verified: true };
    });
  });
  app.post("/api/v1/auth/login", async (req) => {
    await rate(`login:${req.ip}`, 10);
    const b = z
      .object({ email: z.email(), password: z.string().max(128) })
      .strict()
      .parse(req.body);
    return transaction(undefined, async (db) => {
      await rate(`login-account:${digest(b.email.toLowerCase())}`, 10);
      const u = (
        await db.query("SELECT * FROM users WHERE email=$1", [
          b.email.toLowerCase(),
        ])
      ).rows[0];
      const valid = await verifyPassword(b.password, u?.password ?? dummyHash);
      if (!u || !valid || u.status !== "ACTIVE")
        throw new ApiError(
          401,
          "INVALID_CREDENTIALS",
          "Invalid credentials or inactive account",
        );
      const previous = (
        await db.query(
          "SELECT ip FROM sessions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 1",
          [u.id],
        )
      ).rows[0];
      const token = secret();
      await db.query(
        "INSERT INTO sessions(user_id,digest,expires_at,ip,user_agent) VALUES($1,$2,now()+interval '24 hours',$3,$4)",
        [
          u.id,
          digest(token),
          req.ip,
          String(req.headers["user-agent"] ?? "").slice(0, 256),
        ],
      );
      if (previous?.ip && previous.ip !== req.ip)
        await enqueue(db, null, "email", {
          to: u.email,
          subject: "Atlantik security: new sign-in address",
          text: `A login from ${req.ip} was detected. Request ID: ${req.id}. Revoke sessions if this was unexpected.`,
        });
      await db.query(
        "INSERT INTO platform_audit(actor_id,event,request_id,ip,result) VALUES($1,'login',$2,$3,'success')",
        [u.id, req.id, req.ip],
      );
      return { token, expiresIn: 86400 };
    });
  });
  app.post("/api/v1/auth/password-reset/request", async (req) => {
    await rate(`reset:${req.ip}`, 3);
    const b = z.object({ email: z.email() }).strict().parse(req.body);
    await transaction(undefined, async (db) => {
      const u = (
        await db.query(
          "SELECT id,email FROM users WHERE email=$1 AND status='ACTIVE'",
          [b.email.toLowerCase()],
        )
      ).rows[0];
      if (u) {
        await issue(db, u.id, u.email, "reset", null);
      }
    });
    return { accepted: true };
  });
  app.post("/api/v1/auth/password-reset/confirm", async (req) => {
    await rate(`reset-confirm:${req.ip}`, 5);
    const b = z
      .object({ token: z.string().max(200), password })
      .strict()
      .parse(req.body);
    return transaction(undefined, async (db) => {
      const t = (
        await db.query(
          "DELETE FROM tokens WHERE digest=$1 AND kind='reset' AND expires_at>now() RETURNING user_id",
          [digest(b.token)],
        )
      ).rows[0];
      if (!t)
        throw new ApiError(400, "INVALID_TOKEN", "Token invalid or expired");
      const updated = await db.query(
        "UPDATE users SET password=$1 WHERE id=$2 AND status='ACTIVE'",
        [await hashPassword(b.password), t.user_id],
      );
      if (!updated.rowCount)
        throw new ApiError(403, "INACTIVE_ACCOUNT", "Account inactive");
      await db.query("DELETE FROM sessions WHERE user_id=$1", [t.user_id]);
      await db.query(
        "INSERT INTO platform_audit(actor_id,event,request_id,ip,result) VALUES($1,'password.reset',$2,$3,'success')",
        [t.user_id, req.id, req.ip],
      );
      const u = (
        await db.query("SELECT email FROM users WHERE id=$1", [t.user_id])
      ).rows[0];
      await enqueue(db, null, "email", {
        to: u.email,
        subject: "Atlantik password reset",
        text: "Your password was reset and all sessions were revoked.",
      });
      return { changed: true };
    });
  });
  async function tenant(
    req: FastifyRequest,
    permission: string,
    fn: (db: pg.PoolClient, ctx: Context) => Promise<unknown>,
  ) {
    const org = uuid.parse(req.headers["x-organization-id"]);
    const bearer = req.headers.authorization;
    if (typeof bearer !== "string" || bearer.length > 256)
      throw new ApiError(401, "UNAUTHENTICATED", "Bearer credential required");
    if (!bearer.startsWith("Bearer "))
      throw new ApiError(401, "UNAUTHENTICATED", "Bearer credential required");
    await rate(`api:${digest(bearer)}`, 120);
    const outcome = await transaction(org, async (db) => {
      const o = (
        await db.query("SELECT * FROM organizations WHERE id=$1 FOR UPDATE", [
          org,
        ])
      ).rows[0];
      if (!o || o.status !== "ACTIVE")
        throw new ApiError(
          403,
          "ORGANIZATION_INACTIVE",
          "Organization unavailable",
        );
      const token = bearer.slice(7);
      let user: string | null = null;
      let scopes: string[] = [];
      let role = "api_key";
      let authenticated = false;
      if (token.startsWith("atk_")) {
        const key = (
          await db.query(
            "UPDATE api_keys SET last_used=now() WHERE org_id=$1 AND digest=$2 AND revoked_at IS NULL AND expires_at>now() RETURNING scopes",
            [org, digest(token)],
          )
        ).rows[0];
        if (key) {
          scopes = key.scopes;
          authenticated = true;
        }
      } else {
        const u = (
          await db.query(
            "SELECT u.id,m.role,r.permissions AS custom_permissions FROM sessions s JOIN users u ON u.id=s.user_id JOIN memberships m ON m.user_id=u.id AND m.org_id=$2 LEFT JOIN roles r ON r.org_id=m.org_id AND r.id=m.custom_role_id WHERE s.digest=$1 AND s.expires_at>now() AND u.status='ACTIVE'",
            [digest(token), org],
          )
        ).rows[0];
        if (u) {
          authenticated = true;
          user = u.id;
          role = u.role;
          scopes = u.custom_permissions ?? permissions[u.role] ?? [];
        }
      }
      if (!authenticated)
        throw new ApiError(
          401,
          "UNAUTHENTICATED",
          "Credential invalid or expired",
        );
      await db.query("SAVEPOINT atlantik_authorization");
      try {
        requirePermission(scopes, permission);
        if (
          ["SUSPENDED", "CANCELLED"].includes(o.subscription_status) &&
          !["billing.read", "billing.manage"].includes(permission)
        )
          throw new ApiError(
            403,
            "SUBSCRIPTION_INACTIVE",
            "Subscription does not permit resource access",
          );
        if (!["billing.read", "billing.manage"].includes(permission))
          await meter(db, org, "requests", 1);
      } catch (error) {
        await db.query("ROLLBACK TO SAVEPOINT atlantik_authorization");
        await audit(
          db,
          org,
          user,
          `${req.method} ${req.routeOptions.url}`,
          req.id,
          req.ip,
          "failure",
        );
        return { error };
      }
      await db.query("SAVEPOINT operation");
      try {
        const value = await fn(db, { org, user, scopes, role });
        await db.query(
          "UPDATE organizations SET last_activity=now() WHERE id=$1",
          [org],
        );
        if (req.method !== "GET")
          await audit(
            db,
            org,
            user,
            `${req.method} ${req.routeOptions.url}`,
            req.id,
            req.ip,
          );
        return { value };
      } catch (error) {
        await db.query("ROLLBACK TO SAVEPOINT operation");
        await audit(
          db,
          org,
          user,
          `${req.method} ${req.routeOptions.url}`,
          req.id,
          req.ip,
          "failure",
        );
        return { error };
      }
    });
    if ("error" in outcome) throw outcome.error;
    return outcome.value;
  }

  app.get("/api/v1/organization", (req) =>
    tenant(
      req,
      "workspaces.read",
      async (db, c) =>
        (
          await db.query(
            "SELECT id,name,slug,status,owner_id,plan,subscription_status,renewal_at,settings,created_at,last_activity FROM organizations WHERE id=$1",
            [c.org],
          )
        ).rows[0],
    ),
  );
  app.get("/api/v1/users", (req) =>
    tenant(
      req,
      "users.read",
      async (db, c) =>
        (
          await db.query(
            "SELECT u.id,u.name,u.email,m.role FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=$1 LIMIT 100",
            [c.org],
          )
        ).rows,
    ),
  );
  app.patch("/api/v1/users/:id/role", (req) =>
    tenant(req, "users.update", async (db, c) => {
      const id = uuid.parse((req.params as any).id);
      const b = z
        .object({ role: z.enum(["admin", "member"]) })
        .strict()
        .parse(req.body);
      if (c.role !== "owner" && b.role === "admin")
        throw new ApiError(
          403,
          "FORBIDDEN",
          "Only owners can appoint administrators",
        );
      const r = await db.query(
        "UPDATE memberships SET role=$1,custom_role_id=NULL WHERE org_id=$2 AND user_id=$3 AND role<>'owner' AND (role='member' OR $4)",
        [b.role, c.org, id, c.role === "owner"],
      );
      if (!r.rowCount)
        throw new ApiError(404, "NOT_FOUND", "Eligible member not found");
      return { updated: true };
    }),
  );
  app.get("/api/v1/workspaces", (req) =>
    tenant(
      req,
      "workspaces.read",
      async (db, c) =>
        (
          await db.query(
            "SELECT id,name,created_at FROM workspaces w WHERE org_id=$1 AND ($2 OR EXISTS(SELECT 1 FROM workspace_members m WHERE m.org_id=w.org_id AND m.workspace_id=w.id AND m.user_id=$3) OR EXISTS(SELECT 1 FROM workspace_teams wt JOIN team_members tm ON tm.org_id=wt.org_id AND tm.team_id=wt.team_id WHERE wt.org_id=w.org_id AND wt.workspace_id=w.id AND tm.user_id=$3)) LIMIT 100",
            [
              c.org,
              c.user === null || c.scopes.includes("workspaces.manage"),
              c.user,
            ],
          )
        ).rows,
    ),
  );
  app.get("/api/v1/workspaces/:id", (req) =>
    tenant(req, "workspaces.read", async (db, c) => {
      const id = uuid.parse((req.params as any).id);
      const w = (
        await db.query(
          "SELECT id,name,created_at FROM workspaces w WHERE org_id=$1 AND id=$2 AND ($3 OR EXISTS(SELECT 1 FROM workspace_members m WHERE m.org_id=w.org_id AND m.workspace_id=w.id AND m.user_id=$4) OR EXISTS(SELECT 1 FROM workspace_teams wt JOIN team_members tm ON tm.org_id=wt.org_id AND tm.team_id=wt.team_id WHERE wt.org_id=w.org_id AND wt.workspace_id=w.id AND tm.user_id=$4))",
          [
            c.org,
            id,
            c.user === null || c.scopes.includes("workspaces.manage"),
            c.user,
          ],
        )
      ).rows[0];
      if (!w) throw new ApiError(404, "NOT_FOUND", "Workspace not found");
      return w;
    }),
  );
  app.post("/api/v1/workspaces", (req) =>
    tenant(req, "workspaces.create", async (db, c) => {
      const b = z
        .object({ name: z.string().min(1).max(100) })
        .strict()
        .parse(req.body);
      const o = await limits(db, c.org);
      const count = (
        await db.query("SELECT count(*) FROM workspaces WHERE org_id=$1", [
          c.org,
        ])
      ).rows[0];
      if (Number(count.count) >= o.limits.workspaces)
        throw new ApiError(409, "QUOTA_EXCEEDED", "Workspace limit reached");
      const w = (
        await db.query(
          "INSERT INTO workspaces(org_id,name) VALUES($1,$2) RETURNING id,name",
          [c.org, b.name],
        )
      ).rows[0];
      await emit(db, c.org, "workspace.created", w);
      return w;
    }),
  );
  app.get("/api/v1/teams", (req) =>
    tenant(
      req,
      "teams.read",
      async (db, c) =>
        (
          await db.query(
            "SELECT id,name FROM teams WHERE org_id=$1 LIMIT 100",
            [c.org],
          )
        ).rows,
    ),
  );
  app.post("/api/v1/teams", (req) =>
    tenant(req, "teams.create", async (db, c) => {
      const b = z
        .object({ name: z.string().min(1).max(100) })
        .strict()
        .parse(req.body);
      return (
        await db.query(
          "INSERT INTO teams(org_id,name) VALUES($1,$2) RETURNING id,name",
          [c.org, b.name],
        )
      ).rows[0];
    }),
  );
  app.post("/api/v1/api-keys", (req) =>
    tenant(req, "keys.manage", async (db, c) => {
      const b = z
        .object({
          name: z.string().min(1).max(100),
          scopes: z
            .array(
              z.enum([
                "workspaces.read",
                "workspaces.create",
                "workspaces.manage",
                "teams.read",
              ]),
            )
            .min(1),
          expiresAt: z.iso.datetime(),
        })
        .strict()
        .parse(req.body);
      if (Date.parse(b.expiresAt) <= Date.now())
        throw new ApiError(
          400,
          "INVALID_EXPIRY",
          "Expiration must be in the future",
        );
      for (const s of b.scopes) requirePermission(c.scopes, s);
      const token = `atk_${secret()}`;
      const k = (
        await db.query(
          "INSERT INTO api_keys(org_id,name,digest,scopes,expires_at,created_by) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,name,scopes,expires_at",
          [c.org, b.name, digest(token), b.scopes, b.expiresAt, c.user],
        )
      ).rows[0];
      await notify(db, c.org, "api-key.created", { id: k.id, name: k.name });
      return { ...k, secret: token };
    }),
  );
  app.get("/api/v1/api-keys", (req) =>
    tenant(
      req,
      "keys.manage",
      async (db, c) =>
        (
          await db.query(
            "SELECT id,name,scopes,expires_at,revoked_at,last_used,created_at,CASE WHEN revoked_at IS NOT NULL THEN 'REVOKED' WHEN expires_at<=now() THEN 'EXPIRED' ELSE 'ACTIVE' END AS status FROM api_keys WHERE org_id=$1 LIMIT 100",
            [c.org],
          )
        ).rows,
    ),
  );
  app.delete("/api/v1/api-keys/:id", (req) =>
    tenant(req, "keys.manage", async (db, c) => {
      const id = uuid.parse((req.params as any).id);
      const r = await db.query(
        "UPDATE api_keys SET revoked_at=now() WHERE org_id=$1 AND id=$2",
        [c.org, id],
      );
      if (!r.rowCount) throw new ApiError(404, "NOT_FOUND", "Key not found");
      return { revoked: true };
    }),
  );
  app.get("/api/v1/usage", (req) =>
    tenant(
      req,
      "billing.read",
      async (db, c) =>
        (
          await db.query(
            "SELECT period,metric,quantity FROM usage WHERE org_id=$1 UNION ALL SELECT date_trunc('month',now() AT TIME ZONE 'UTC')::date,'users',count(*) FROM memberships WHERE org_id=$1 UNION ALL SELECT date_trunc('month',now() AT TIME ZONE 'UTC')::date,'workspaces',count(*) FROM workspaces WHERE org_id=$1 ORDER BY period DESC LIMIT 100",
            [c.org],
          )
        ).rows,
    ),
  );
  app.get("/api/v1/audit-logs", (req) =>
    tenant(
      req,
      "audit.read",
      async (db, c) =>
        (
          await db.query(
            "SELECT actor_id,event,request_id,ip,result,created_at FROM audit_logs WHERE org_id=$1 ORDER BY created_at DESC LIMIT 100",
            [c.org],
          )
        ).rows,
    ),
  );
  app.get("/api/v1/notifications", (req) =>
    tenant(
      req,
      "workspaces.read",
      async (db, c) =>
        (
          await db.query(
            "SELECT id,type,payload,read_at,created_at FROM notifications WHERE org_id=$1 AND user_id=$2 ORDER BY created_at DESC LIMIT 100",
            [c.org, c.user],
          )
        ).rows,
    ),
  );
  featureRoutes(app, {
    tenant,
    rate,
    issue,
    monitor: async () => {
      await pool.query("SELECT 1");
      await redis.ping();
      return {
        database: true,
        redis: true,
        queue: true,
        heartbeats: (
          await pool.query("SELECT name,updated_at FROM service_heartbeats")
        ).rows,
        requests: Object.fromEntries(metrics),
      };
    },
  });
  app.addHook("onClose", async () => {
    redis.disconnect();
  });
  return app;
}
