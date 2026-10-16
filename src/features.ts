import type { FastifyInstance, FastifyRequest } from "fastify";
import type pg from "pg";
import { z } from "zod";
import { randomUUID } from "node:crypto";
import { pool, transaction } from "./db.js";
import {
  ApiError,
  digest,
  secret,
  hashPassword,
  verifyPassword,
  permissions,
  requirePermission,
} from "./core.js";
import { encrypt, webhookUrl, validSignature } from "./security.js";
import {
  enqueue,
  event,
  notify,
  limits,
  meter,
  audit,
  type Context,
} from "./services.js";
const uuid = z.string().uuid();
const name = z.string().min(1).max(100);
const password = z.string().min(12).max(128);
const id = (req: FastifyRequest, key = "id") =>
  uuid.parse((req.params as Record<string, string>)[key]);
export async function identity(db: pg.PoolClient, req: FastifyRequest) {
  const h = req.headers.authorization;
  if (!h?.startsWith("Bearer ") || h.length > 256)
    throw new ApiError(401, "UNAUTHENTICATED", "Session required");
  const u = (
    await db.query(
      "SELECT u.id,u.name,u.email,u.platform_admin FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.digest=$1 AND s.expires_at>now() AND u.status='ACTIVE'",
      [digest(h.slice(7))],
    )
  ).rows[0];
  if (!u)
    throw new ApiError(401, "UNAUTHENTICATED", "Session invalid or expired");
  return u;
}
type Dependencies = {
  monitor: () => Promise<unknown>;
  tenant: (
    req: FastifyRequest,
    permission: string,
    fn: (db: pg.PoolClient, c: Context) => Promise<unknown>,
  ) => Promise<unknown>;
  rate: (key: string, limit: number) => Promise<void>;
  issue: (
    db: pg.PoolClient,
    user: string,
    email: string,
    kind: string,
    org: string | null,
  ) => Promise<void>;
};
export function featureRoutes(
  app: FastifyInstance,
  { tenant, rate, issue, monitor }: Dependencies,
) {
  const session = async (
    req: FastifyRequest,
    fn: (db: pg.PoolClient, u: any) => Promise<unknown>,
  ) => {
    await rate(`session:${req.ip}`, 120);
    return transaction(undefined, async (db) =>
      fn(db, await identity(db, req)),
    );
  };
  app.post("/api/v1/auth/logout", (req) =>
    session(req, async (db) => {
      await db.query("DELETE FROM sessions WHERE digest=$1", [
        digest(req.headers.authorization!.slice(7)),
      ]);
      return { revoked: true };
    }),
  );
  app.get("/api/v1/me", (req) =>
    session(req, async (_db, u) => ({
      id: u.id,
      name: u.name,
      email: u.email,
    })),
  );
  app.patch("/api/v1/me", (req) =>
    session(req, async (db, u) => {
      const b = z.object({ name }).strict().parse(req.body);
      await db.query("UPDATE users SET name=$1 WHERE id=$2", [b.name, u.id]);
      return { updated: true };
    }),
  );
  app.post("/api/v1/auth/password/change", (req) =>
    session(req, async (db, u) => {
      const b = z
        .object({ currentPassword: z.string().max(128), password })
        .strict()
        .parse(req.body);
      const current = (
        await db.query("SELECT password FROM users WHERE id=$1 FOR UPDATE", [
          u.id,
        ])
      ).rows[0];
      if (!(await verifyPassword(b.currentPassword, current.password)))
        throw new ApiError(
          401,
          "INVALID_CREDENTIALS",
          "Current password invalid",
        );
      await db.query("UPDATE users SET password=$1 WHERE id=$2", [
        await hashPassword(b.password),
        u.id,
      ]);
      await db.query("DELETE FROM sessions WHERE user_id=$1", [u.id]);
      await db.query("DELETE FROM tokens WHERE user_id=$1", [u.id]);
      await enqueue(db, null, "email", {
        to: u.email,
        subject: "Atlantik password changed",
        text: "Your password changed. All sessions were revoked.",
      });
      await db.query(
        "INSERT INTO platform_audit(actor_id,event,request_id,ip,result) VALUES($1,'password.changed',$2,$3,'success')",
        [u.id, req.id, req.ip],
      );
      return { changed: true, reauthenticationRequired: true };
    }),
  );
  app.post("/api/v1/auth/email/change", (req) =>
    session(req, async (db, u) => {
      const b = z
        .object({ email: z.email().max(254), password: z.string().max(128) })
        .strict()
        .parse(req.body);
      const current = (
        await db.query("SELECT password FROM users WHERE id=$1 FOR UPDATE", [
          u.id,
        ])
      ).rows[0];
      if (!(await verifyPassword(b.password, current.password)))
        throw new ApiError(
          401,
          "INVALID_CREDENTIALS",
          "Current password invalid",
        );
      await db.query(
        "UPDATE users SET email=$1,status='PENDING_VERIFICATION' WHERE id=$2",
        [b.email.toLowerCase(), u.id],
      );
      await db.query("DELETE FROM sessions WHERE user_id=$1", [u.id]);
      await db.query("DELETE FROM tokens WHERE user_id=$1", [u.id]);
      await issue(db, u.id, b.email.toLowerCase(), "verify", null);
      return { verificationRequired: true };
    }),
  );
  app.post("/api/v1/auth/verification/resend", async (req) => {
    await rate(`resend:${req.ip}`, 3);
    const b = z.object({ email: z.email() }).strict().parse(req.body);
    await transaction(undefined, async (db) => {
      const u = (
        await db.query(
          "SELECT id,email FROM users WHERE email=$1 AND status='PENDING_VERIFICATION' FOR UPDATE",
          [b.email.toLowerCase()],
        )
      ).rows[0];
      if (u) await issue(db, u.id, u.email, "verify", null);
    });
    return { accepted: true };
  });
  app.get("/api/v1/auth/sessions", (req) =>
    session(
      req,
      async (db, u) =>
        (
          await db.query(
            "SELECT id,created_at,expires_at,ip,user_agent FROM sessions WHERE user_id=$1 AND expires_at>now() ORDER BY created_at DESC LIMIT 100",
            [u.id],
          )
        ).rows,
    ),
  );
  app.delete("/api/v1/auth/sessions/:id", (req) =>
    session(req, async (db, u) => {
      await db.query("DELETE FROM sessions WHERE id=$1 AND user_id=$2", [
        id(req),
        u.id,
      ]);
      return { revoked: true };
    }),
  );
  app.get("/api/v1/organizations", (req) =>
    session(
      req,
      async (db) =>
        (
          await db.query("SELECT * FROM account_organizations($1)", [
            digest(req.headers.authorization!.slice(7)),
          ])
        ).rows,
    ),
  );
  app.post("/api/v1/organizations", (req) =>
    session(req, async (db, u) => {
      const b = z
        .object({ name, slug: z.string().regex(/^[a-z0-9-]{3,60}$/) })
        .strict()
        .parse(req.body);
      const orgId = randomUUID();
      await db.query("SELECT set_config('app.org_id',$1,true)", [orgId]);
      const o = (
        await db.query(
          "INSERT INTO organizations(id,name,slug,owner_id) VALUES($1,$2,$3,$4) RETURNING id,name,slug",
          [orgId, b.name, b.slug, u.id],
        )
      ).rows[0];
      await db.query(
        "INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')",
        [o.id, u.id],
      );
      await audit(db, o.id, u.id, "organization.created", req.id, req.ip);
      return o;
    }),
  );
  app.patch("/api/v1/organization", (req) =>
    tenant(req, "organization.manage", async (db, c) => {
      const b = z
        .object({
          name: name.optional(),
          settings: z
            .record(
              z.string().max(100),
              z.union([
                z.string().max(1000),
                z.number(),
                z.boolean(),
                z.null(),
              ]),
            )
            .optional(),
        })
        .strict()
        .parse(req.body);
      await db.query(
        "UPDATE organizations SET name=coalesce($1,name),settings=coalesce($2,settings) WHERE id=$3",
        [b.name, b.settings, c.org],
      );
      return { updated: true };
    }),
  );
  app.delete("/api/v1/organization", (req) =>
    tenant(req, "organization.delete", async (db, c) => {
      if (c.role !== "owner")
        throw new ApiError(403, "FORBIDDEN", "Owner required");
      await db.query("UPDATE organizations SET status='DELETED' WHERE id=$1", [
        c.org,
      ]);
      return { deleted: true };
    }),
  );
  app.post("/api/v1/organization/transfer", (req) =>
    tenant(req, "ownership.transfer", async (db, c) => {
      if (c.role !== "owner")
        throw new ApiError(403, "FORBIDDEN", "Owner required");
      const b = z
        .object({ userId: uuid, password: z.string().max(128) })
        .strict()
        .parse(req.body);
      if (c.user === b.userId)
        throw new ApiError(400, "INVALID_TRANSFER", "Choose another member");
      const u = (
        await db.query("SELECT password FROM users WHERE id=$1 FOR UPDATE", [
          c.user,
        ])
      ).rows[0];
      if (!(await verifyPassword(b.password, u.password)))
        throw new ApiError(
          401,
          "INVALID_CREDENTIALS",
          "Current password invalid",
        );
      const member = (
        await db.query(
          "SELECT m.user_id FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=$1 AND m.user_id=$2 AND u.status='ACTIVE'",
          [c.org, b.userId],
        )
      ).rows[0];
      if (!member)
        throw new ApiError(404, "NOT_FOUND", "Active member not found");
      await db.query(
        "UPDATE memberships SET role='admin',custom_role_id=NULL WHERE org_id=$1 AND user_id=$2",
        [c.org, c.user],
      );
      await db.query(
        "UPDATE memberships SET role='owner',custom_role_id=NULL WHERE org_id=$1 AND user_id=$2",
        [c.org, b.userId],
      );
      await db.query("UPDATE organizations SET owner_id=$1 WHERE id=$2", [
        b.userId,
        c.org,
      ]);
      return { transferred: true };
    }),
  );
  app.post("/api/v1/invitations", (req) =>
    tenant(req, "users.create", async (db, c) => {
      const b = z
        .object({
          email: z.email().max(254),
          role: z.enum(["admin", "member"]).default("member"),
        })
        .strict()
        .parse(req.body);
      if (b.role === "admin" && c.role !== "owner")
        throw new ApiError(403, "FORBIDDEN", "Owner required");
      const o = await limits(db, c.org);
      const count = (
        await db.query("SELECT count(*) FROM memberships WHERE org_id=$1", [
          c.org,
        ])
      ).rows[0];
      const pending = (
        await db.query(
          "SELECT count(*) FROM invitations WHERE org_id=$1 AND accepted_at IS NULL AND expires_at>now()",
          [c.org],
        )
      ).rows[0];
      if (Number(count.count) + Number(pending.count) >= o.limits.users)
        throw new ApiError(409, "QUOTA_EXCEEDED", "User limit reached");
      await db.query(
        "DELETE FROM invitations WHERE org_id=$1 AND email=$2 AND accepted_at IS NULL AND expires_at<=now()",
        [c.org, b.email.toLowerCase()],
      );
      const token = secret();
      const i = (
        await db.query(
          "INSERT INTO invitations(org_id,email,role,digest,expires_at) VALUES($1,$2,$3,$4,now()+interval '48 hours') RETURNING id,email,role,expires_at",
          [c.org, b.email.toLowerCase(), b.role, digest(token)],
        )
      ).rows[0];
      await enqueue(db, c.org, "email", {
        to: i.email,
        subject: "Atlantik invitation",
        text: `Organization: ${c.org}. Invitation token: ${token}`,
      });
      return i;
    }),
  );
  app.get("/api/v1/invitations", (req) =>
    tenant(
      req,
      "users.read",
      async (db, c) =>
        (
          await db.query(
            "SELECT id,email,role,expires_at,accepted_at FROM invitations WHERE org_id=$1 LIMIT 100",
            [c.org],
          )
        ).rows,
    ),
  );
  app.post("/api/v1/invitations/accept", (req) =>
    session(req, async (db, u) => {
      const b = z
        .object({ organizationId: uuid, token: z.string().min(20).max(200) })
        .strict()
        .parse(req.body);
      await db.query("SELECT set_config('app.org_id',$1,true)", [
        b.organizationId,
      ]);
      const o = await limits(db, b.organizationId);
      if (
        o.status !== "ACTIVE" ||
        ["CANCELLED", "SUSPENDED"].includes(o.subscription_status)
      )
        throw new ApiError(
          403,
          "ORGANIZATION_INACTIVE",
          "Organization unavailable",
        );
      const i = (
        await db.query(
          "UPDATE invitations SET accepted_at=now() WHERE org_id=$1 AND digest=$2 AND email=$3 AND accepted_at IS NULL AND expires_at>now() RETURNING role",
          [b.organizationId, digest(b.token), u.email],
        )
      ).rows[0];
      if (!i)
        throw new ApiError(
          400,
          "INVALID_TOKEN",
          "Invitation invalid or expired",
        );
      const count = (
        await db.query("SELECT count(*) FROM memberships WHERE org_id=$1", [
          b.organizationId,
        ])
      ).rows[0];
      if (Number(count.count) >= o.limits.users)
        throw new ApiError(409, "QUOTA_EXCEEDED", "User limit reached");
      await db.query(
        "INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,$3)",
        [b.organizationId, u.id, i.role],
      );
      await event(db, b.organizationId, "user.created", { userId: u.id });
      await audit(
        db,
        b.organizationId,
        u.id,
        "invitation.accepted",
        req.id,
        req.ip,
      );
      return { accepted: true };
    }),
  );
  app.delete("/api/v1/users/:id", (req) =>
    tenant(req, "users.delete", async (db, c) => {
      const user = id(req);
      const member = (
        await db.query(
          "SELECT role FROM memberships WHERE org_id=$1 AND user_id=$2",
          [c.org, user],
        )
      ).rows[0];
      if (!member) throw new ApiError(404, "NOT_FOUND", "Member not found");
      if (
        member.role === "owner" ||
        (member.role === "admin" && c.role !== "owner")
      )
        throw new ApiError(403, "FORBIDDEN", "Cannot remove this member");
      await db.query(
        "DELETE FROM workspace_members WHERE org_id=$1 AND user_id=$2",
        [c.org, user],
      );
      await db.query(
        "DELETE FROM team_members WHERE org_id=$1 AND user_id=$2",
        [c.org, user],
      );
      await db.query("DELETE FROM memberships WHERE org_id=$1 AND user_id=$2", [
        c.org,
        user,
      ]);
      await db.query(
        "UPDATE api_keys SET revoked_at=now() WHERE org_id=$1 AND created_by=$2",
        [c.org, user],
      );
      await event(db, c.org, "user.deleted", { userId: user });
      return { removed: true };
    }),
  );
  app.post("/api/v1/roles", (req) =>
    tenant(req, "roles.manage", async (db, c) => {
      const b = z
        .object({ name, permissions: z.array(z.string()).max(50) })
        .strict()
        .parse(req.body);
      const allowed = permissions.admin;
      for (const p of b.permissions) {
        if (!allowed.includes(p))
          throw new ApiError(
            403,
            "FORBIDDEN",
            "Custom roles cannot grant owner permissions",
          );
        requirePermission(c.scopes, p);
      }
      return (
        await db.query(
          "INSERT INTO roles(org_id,name,permissions) VALUES($1,$2,$3) RETURNING id,name,permissions",
          [c.org, b.name, b.permissions],
        )
      ).rows[0];
    }),
  );
  app.patch("/api/v1/roles/:id", (req) =>
    tenant(req, "roles.manage", async (db, c) => {
      const b = z
        .object({ permissions: z.array(z.string()).max(50) })
        .strict()
        .parse(req.body);
      if (b.permissions.some((p) => !permissions.admin.includes(p)))
        throw new ApiError(
          403,
          "FORBIDDEN",
          "Custom roles cannot grant owner permissions",
        );
      const r = await db.query(
        "UPDATE roles SET permissions=$1 WHERE org_id=$2 AND id=$3",
        [b.permissions, c.org, id(req)],
      );
      if (!r.rowCount) throw new ApiError(404, "NOT_FOUND", "Role not found");
      return { updated: true };
    }),
  );
  app.delete("/api/v1/roles/:id", (req) =>
    tenant(req, "roles.manage", async (db, c) => {
      const r = await db.query("DELETE FROM roles WHERE org_id=$1 AND id=$2", [
        c.org,
        id(req),
      ]);
      if (!r.rowCount) throw new ApiError(404, "NOT_FOUND", "Role not found");
      return { deleted: true };
    }),
  );
  app.get("/api/v1/teams/:id/members", (req) =>
    tenant(
      req,
      "teams.read",
      async (db, c) =>
        (
          await db.query(
            "SELECT u.id,u.name FROM team_members tm JOIN users u ON u.id=tm.user_id WHERE tm.org_id=$1 AND tm.team_id=$2 LIMIT 100",
            [c.org, id(req)],
          )
        ).rows,
    ),
  );
  app.delete("/api/v1/workspaces/:id/teams/:teamId", (req) =>
    tenant(req, "workspaces.manage", async (db, c) => {
      await db.query(
        "DELETE FROM workspace_teams WHERE org_id=$1 AND workspace_id=$2 AND team_id=$3",
        [c.org, id(req), id(req, "teamId")],
      );
      return { removed: true };
    }),
  );
  app.patch("/api/v1/workspaces/:id", (req) =>
    tenant(req, "workspaces.manage", async (db, c) => {
      const b = z.object({ name }).strict().parse(req.body);
      const w = (
        await db.query(
          "UPDATE workspaces SET name=$1 WHERE org_id=$2 AND id=$3 RETURNING id,name",
          [b.name, c.org, id(req)],
        )
      ).rows[0];
      if (!w) throw new ApiError(404, "NOT_FOUND", "Workspace not found");
      return w;
    }),
  );
  app.get("/api/v1/roles", (req) =>
    tenant(req, "users.read", async (db, c) => ({
      builtIn: permissions,
      custom: (
        await db.query(
          "SELECT id,name,permissions FROM roles WHERE org_id=$1 LIMIT 100",
          [c.org],
        )
      ).rows,
    })),
  );
  app.put("/api/v1/users/:id/custom-role", (req) =>
    tenant(req, "roles.manage", async (db, c) => {
      const b = z.object({ roleId: uuid }).strict().parse(req.body);
      const r = (
        await db.query(
          "SELECT permissions FROM roles WHERE org_id=$1 AND id=$2",
          [c.org, b.roleId],
        )
      ).rows[0];
      if (!r) throw new ApiError(404, "NOT_FOUND", "Role not found");
      const updated = await db.query(
        "UPDATE memberships SET custom_role_id=$1 WHERE org_id=$2 AND user_id=$3 AND role='member'",
        [b.roleId, c.org, id(req)],
      );
      if (!updated.rowCount)
        throw new ApiError(404, "NOT_FOUND", "Eligible member not found");
      return { updated: true };
    }),
  );
  app.delete("/api/v1/teams/:id", (req) =>
    tenant(req, "teams.delete", async (db, c) => {
      const r = await db.query("DELETE FROM teams WHERE org_id=$1 AND id=$2", [
        c.org,
        id(req),
      ]);
      if (!r.rowCount) throw new ApiError(404, "NOT_FOUND", "Team not found");
      return { deleted: true };
    }),
  );
  app.put("/api/v1/teams/:id/members/:userId", (req) =>
    tenant(req, "teams.create", async (db, c) => {
      const team = id(req);
      const user = id(req, "userId");
      const r = await db.query(
        "INSERT INTO team_members(org_id,team_id,user_id) SELECT $1,$2,$3 WHERE EXISTS(SELECT 1 FROM teams WHERE org_id=$1 AND id=$2) AND EXISTS(SELECT 1 FROM memberships WHERE org_id=$1 AND user_id=$3) ON CONFLICT DO NOTHING RETURNING user_id",
        [c.org, team, user],
      );
      if (!r.rowCount)
        throw new ApiError(
          409,
          "MEMBERSHIP_NOT_CREATED",
          "Membership exists or tenant resource not found",
        );
      return { added: true };
    }),
  );
  app.delete("/api/v1/teams/:id/members/:userId", (req) =>
    tenant(req, "teams.create", async (db, c) => {
      await db.query(
        "DELETE FROM team_members WHERE org_id=$1 AND team_id=$2 AND user_id=$3",
        [c.org, id(req), id(req, "userId")],
      );
      return { removed: true };
    }),
  );
  app.put("/api/v1/workspaces/:id/members/:userId", (req) =>
    tenant(req, "workspaces.manage", async (db, c) => {
      const r = await db.query(
        "INSERT INTO workspace_members(org_id,workspace_id,user_id) SELECT $1,$2,$3 WHERE EXISTS(SELECT 1 FROM workspaces WHERE org_id=$1 AND id=$2) AND EXISTS(SELECT 1 FROM memberships WHERE org_id=$1 AND user_id=$3) ON CONFLICT DO NOTHING RETURNING user_id",
        [c.org, id(req), id(req, "userId")],
      );
      if (!r.rowCount)
        throw new ApiError(
          409,
          "MEMBERSHIP_NOT_CREATED",
          "Membership exists or tenant resource not found",
        );
      return { added: true };
    }),
  );
  app.delete("/api/v1/workspaces/:id/members/:userId", (req) =>
    tenant(req, "workspaces.manage", async (db, c) => {
      await db.query(
        "DELETE FROM workspace_members WHERE org_id=$1 AND workspace_id=$2 AND user_id=$3",
        [c.org, id(req), id(req, "userId")],
      );
      return { removed: true };
    }),
  );
  app.put("/api/v1/workspaces/:id/teams/:teamId", (req) =>
    tenant(req, "workspaces.manage", async (db, c) => {
      const r = await db.query(
        "INSERT INTO workspace_teams(org_id,workspace_id,team_id) SELECT $1,$2,$3 WHERE EXISTS(SELECT 1 FROM workspaces WHERE org_id=$1 AND id=$2) AND EXISTS(SELECT 1 FROM teams WHERE org_id=$1 AND id=$3) ON CONFLICT DO NOTHING RETURNING team_id",
        [c.org, id(req), id(req, "teamId")],
      );
      if (!r.rowCount)
        throw new ApiError(
          409,
          "MEMBERSHIP_NOT_CREATED",
          "Access exists or tenant resource not found",
        );
      return { added: true };
    }),
  );
  app.delete("/api/v1/workspaces/:id", (req) =>
    tenant(req, "workspaces.manage", async (db, c) => {
      const r = await db.query(
        "DELETE FROM workspaces WHERE org_id=$1 AND id=$2",
        [c.org, id(req)],
      );
      if (!r.rowCount)
        throw new ApiError(404, "NOT_FOUND", "Workspace not found");
      return { deleted: true };
    }),
  );
  app.post("/api/v1/api-keys/:id/rotate", (req) =>
    tenant(req, "keys.manage", async (db, c) => {
      const token = `atk_${secret()}`;
      const k = (
        await db.query(
          "UPDATE api_keys SET digest=$1 WHERE org_id=$2 AND id=$3 AND revoked_at IS NULL AND expires_at>now() RETURNING id,name,scopes,expires_at",
          [digest(token), c.org, id(req)],
        )
      ).rows[0];
      if (!k) throw new ApiError(404, "NOT_FOUND", "Active key not found");
      await notify(db, c.org, "api-key.rotated", { id: k.id });
      return { ...k, secret: token };
    }),
  );
  app.get("/api/v1/plans", (req) =>
    session(
      req,
      async (db) =>
        (await db.query("SELECT id,limits FROM plans ORDER BY id")).rows,
    ),
  );
  app.get("/api/v1/subscription", (req) =>
    tenant(req, "billing.read", async (db, c) => {
      const o = await limits(db, c.org);
      return {
        plan: o.plan,
        status: o.subscription_status,
        startedAt: o.subscription_started_at,
        renewalAt: o.renewal_at,
        limits: o.limits,
      };
    }),
  );
  // Simulated checkout is explicitly opt-in for development. Production plan updates require signed provider events.
  app.patch("/api/v1/subscription", (req) =>
    tenant(req, "billing.manage", async (db, c) => {
      if (process.env.BILLING_MODE !== "simulation")
        throw new ApiError(
          409,
          "BILLING_PROVIDER_REQUIRED",
          "A billing provider is required",
        );
      const b = z
        .object({
          plan: z.enum(["free", "pro"]),
          status: z.enum(["ACTIVE", "CANCELLED"]),
        })
        .strict()
        .parse(req.body);
      await db.query(
        "UPDATE organizations SET plan=$1,subscription_status=$2,renewal_at=now()+interval '1 month' WHERE id=$3",
        [b.plan, b.status, c.org],
      );
      await event(db, c.org, "subscription.updated", b);
      await notify(db, c.org, "subscription.updated", b);
      return { updated: true };
    }),
  );
  app.post("/api/v1/reports/usage", (req) =>
    tenant(req, "billing.read", async (db, c) => {
      await meter(db, c.org, "jobs", 1);
      await enqueue(db, c.org, "usage-report", {});
      return { accepted: true };
    }),
  );
  app.post("/api/v1/usage/events", (req) =>
    tenant(req, "usage.write", async (db, c) => {
      const b = z
        .object({
          eventId: z.string().min(1).max(100),
          metric: z.enum(["storage", "jobs", "bandwidth"]),
          quantity: z
            .number()
            .int()
            .min(-Number.MAX_SAFE_INTEGER)
            .max(Number.MAX_SAFE_INTEGER)
            .refine((v) => v !== 0),
        })
        .strict()
        .parse(req.body);
      if (b.quantity < 0 && b.metric !== "storage")
        throw new ApiError(
          400,
          "INVALID_USAGE",
          "Only storage releases may be negative",
        );
      return meter(db, c.org, b.metric, b.quantity, b.eventId);
    }),
  );
  app.post("/api/v1/webhooks", (req) =>
    tenant(req, "webhooks.manage", async (db, c) => {
      const b = z
        .object({ url: z.url().max(2048) })
        .strict()
        .parse(req.body);
      const token = secret();
      const w = (
        await db.query(
          "INSERT INTO webhooks(org_id,url,secret) VALUES($1,$2,$3) RETURNING id,url,enabled,created_at",
          [c.org, webhookUrl(b.url), encrypt(token)],
        )
      ).rows[0];
      return { ...w, secret: token };
    }),
  );
  app.get("/api/v1/webhooks", (req) =>
    tenant(
      req,
      "webhooks.manage",
      async (db, c) =>
        (
          await db.query(
            "SELECT id,url,enabled,created_at FROM webhooks WHERE org_id=$1 LIMIT 100",
            [c.org],
          )
        ).rows,
    ),
  );
  app.patch("/api/v1/webhooks/:id", (req) =>
    tenant(req, "webhooks.manage", async (db, c) => {
      const b = z.object({ enabled: z.boolean() }).strict().parse(req.body);
      const r = await db.query(
        "UPDATE webhooks SET enabled=$1 WHERE org_id=$2 AND id=$3",
        [b.enabled, c.org, id(req)],
      );
      if (!r.rowCount)
        throw new ApiError(404, "NOT_FOUND", "Webhook not found");
      return { updated: true };
    }),
  );
  app.get("/api/v1/webhook-deliveries", (req) =>
    tenant(
      req,
      "webhooks.manage",
      async (db, c) =>
        (
          await db.query(
            "SELECT id,webhook_id,event_id,status,attempts,http_status,last_error,created_at,completed_at FROM webhook_deliveries WHERE org_id=$1 ORDER BY created_at DESC LIMIT 100",
            [c.org],
          )
        ).rows,
    ),
  );
  app.patch("/api/v1/notifications/:id/read", (req) =>
    tenant(req, "workspaces.read", async (db, c) => {
      await db.query(
        "UPDATE notifications SET read_at=now() WHERE org_id=$1 AND id=$2 AND user_id=$3",
        [c.org, id(req), c.user],
      );
      return { updated: true };
    }),
  );
  const platform = async (
    req: FastifyRequest,
    fn: (db: pg.PoolClient, u: any) => Promise<unknown>,
  ) =>
    session(req, async (db, u) => {
      if (!u.platform_admin)
        throw new ApiError(403, "FORBIDDEN", "Platform administrator required");
      const r = await fn(db, u);
      await db.query(
        "INSERT INTO platform_audit(actor_id,event,request_id,ip,result) VALUES($1,$2,$3,$4,'success')",
        [u.id, `${req.method} ${req.routeOptions.url}`, req.id, req.ip],
      );
      return r;
    });
  app.get("/api/v1/platform/organizations", (req) =>
    platform(
      req,
      async (db) =>
        (
          await db.query("SELECT * FROM platform_organizations($1)", [
            digest(req.headers.authorization!.slice(7)),
          ])
        ).rows,
    ),
  );
  app.patch("/api/v1/platform/organizations/:id/status", (req) =>
    platform(req, async (db, u) => {
      const b = z
        .object({
          status: z.enum(["ACTIVE", "SUSPENDED", "PENDING", "DELETED"]),
        })
        .strict()
        .parse(req.body);
      const org = id(req);
      const r = (
        await db.query(
          "SELECT platform_organization_status($1,$2,$3) AS updated",
          [digest(req.headers.authorization!.slice(7)), org, b.status],
        )
      ).rows[0];
      if (!r.updated)
        throw new ApiError(
          404,
          "NOT_FOUND",
          "Organization not found or deleted",
        );
      await db.query("SELECT set_config('app.org_id',$1,true)", [org]);
      await notify(db, org, `organization.${b.status.toLowerCase()}`, {
        status: b.status,
      });
      await audit(db, org, u.id, "organization.status.changed", req.id, req.ip);
      return { updated: true };
    }),
  );
  app.patch("/api/v1/platform/users/:id/status", (req) =>
    platform(req, async (db) => {
      const b = z
        .object({ status: z.enum(["ACTIVE", "SUSPENDED", "DEACTIVATED"]) })
        .strict()
        .parse(req.body);
      const r = await db.query(
        "UPDATE users SET status=$1 WHERE id=$2 AND status<>'PENDING_VERIFICATION'",
        [b.status, id(req)],
      );
      if (!r.rowCount)
        throw new ApiError(404, "NOT_FOUND", "Verified account not found");
      if (b.status !== "ACTIVE")
        await db.query("DELETE FROM sessions WHERE user_id=$1", [id(req)]);
      return { updated: true };
    }),
  );
  app.get("/api/v1/platform/statistics", (req) =>
    platform(
      req,
      async (db) =>
        (
          await db.query("SELECT platform_statistics($1) AS statistics", [
            digest(req.headers.authorization!.slice(7)),
          ])
        ).rows[0].statistics,
    ),
  );
  app.get("/api/v1/platform/health", (req) =>
    platform(req, async () => monitor()),
  );
  app.get("/api/v1/platform/audit-logs", (req) =>
    platform(
      req,
      async (db) =>
        (
          await db.query(
            "SELECT actor_id,event,request_id,ip,result,created_at FROM platform_audit ORDER BY created_at DESC LIMIT 100",
          )
        ).rows,
    ),
  );
  app.get("/api/v1/platform/config", (req) =>
    platform(
      req,
      async (db) =>
        (
          await db.query(
            "SELECT key,value,updated_at FROM platform_config ORDER BY key",
          )
        ).rows,
    ),
  );
  app.put("/api/v1/platform/config/:key", (req) =>
    platform(req, async (db) => {
      const k = z
        .enum(["maintenance", "signupEnabled"])
        .parse((req.params as any).key);
      const b = z.object({ value: z.boolean() }).strict().parse(req.body);
      await db.query(
        "INSERT INTO platform_config(key,value) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()",
        [k, JSON.stringify(b.value)],
      );
      return { updated: true };
    }),
  );
  // Provider signature covers the exact received bytes; this plugin bypasses JSON parsing for this route only.
  app.register(async (scope) => {
    scope.removeContentTypeParser("application/json");
    scope.addContentTypeParser(
      "application/json",
      { parseAs: "string" },
      (_req, body, done) => done(null, body),
    );
    scope.post("/api/v1/billing/events", async (req) => {
      await rate(`billing:${req.ip}`, 120);
      const raw = String(req.body);
      const ts = String(req.headers["x-atlantik-timestamp"] ?? "");
      const sig = String(req.headers["x-atlantik-signature"] ?? "");
      const providerSecret = process.env.BILLING_WEBHOOK_SECRET;
      if (!providerSecret || !validSignature(providerSecret, ts, raw, sig))
        throw new ApiError(
          401,
          "INVALID_SIGNATURE",
          "Billing signature invalid or expired",
        );
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        throw new ApiError(400, "INVALID_INPUT", "Invalid JSON");
      }
      const b = z
        .object({
          id: z.string().min(1).max(100),
          organizationId: uuid,
          type: z.enum([
            "subscription.created",
            "subscription.updated",
            "subscription.cancelled",
            "payment.succeeded",
            "payment.failed",
          ]),
          version: z.number().int().positive(),
          plan: z.string().max(50).optional(),
        })
        .strict()
        .parse(parsed);
      return transaction(b.organizationId, async (db) => {
        const o = await limits(db, b.organizationId);
        const existing = await db.query(
          "INSERT INTO billing_events(id,org_id,type,payload) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING RETURNING id",
          [b.id, b.organizationId, b.type, b],
        );
        if (!existing.rowCount) return { accepted: true, duplicate: true };
        await enqueue(db, b.organizationId, "billing", b);
        return { accepted: true };
      });
    });
  });
}
