import type pg from "pg";
import { encrypt } from "./security.js";
import { ApiError } from "./core.js";
export type Context = {
  org: string;
  user: string | null;
  scopes: string[];
  role: string;
};
export async function enqueue(
  db: pg.PoolClient,
  org: string | null,
  type: string,
  payload: unknown,
) {
  await db.query("INSERT INTO outbox(org_id,type,payload) VALUES($1,$2,$3)", [
    org,
    type,
    { encrypted: encrypt(payload) },
  ]);
}
export async function notify(
  db: pg.PoolClient,
  org: string,
  type: string,
  payload: unknown,
) {
  const members = (
    await db.query(
      "SELECT u.id,u.email FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.org_id=$1 AND m.role='owner'",
      [org],
    )
  ).rows;
  for (const u of members) {
    await db.query(
      "INSERT INTO notifications(org_id,user_id,type,payload) VALUES($1,$2,$3,$4)",
      [org, u.id, type, payload],
    );
    await enqueue(db, org, "email", {
      to: u.email,
      subject: `Atlantik: ${type}`,
      text: JSON.stringify(payload),
    });
  }
}
export async function event(
  db: pg.PoolClient,
  org: string,
  type: string,
  payload: unknown,
) {
  await enqueue(db, org, "event", { type, data: payload });
}
export async function limits(db: pg.PoolClient, org: string) {
  const o = (
    await db.query(
      "SELECT o.id,o.status,o.plan,o.subscription_status,o.subscription_started_at,o.subscription_version,o.renewal_at,p.limits FROM organizations o JOIN plans p ON p.id=o.plan WHERE o.id=$1 FOR UPDATE OF o",
      [org],
    )
  ).rows[0];
  if (!o) throw new ApiError(404, "NOT_FOUND", "Organization not found");
  return o;
}
export async function meter(
  db: pg.PoolClient,
  org: string,
  metric: string,
  amount: number,
  eventId?: string,
) {
  const o = await limits(db, org);
  const limit = o.limits[metric];
  if (!Number.isSafeInteger(limit) || limit < 0)
    throw new ApiError(403, "PLAN_UNCONFIGURED", "Metric limit not configured");
  if (eventId) {
    const r = await db.query(
      "INSERT INTO usage_events(org_id,id,metric,quantity) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING id",
      [org, eventId, metric, amount],
    );
    if (!r.rowCount) return { duplicate: true };
  }
  if (metric === "storage") {
    const existing = (
      await db.query(
        "SELECT quantity FROM usage WHERE org_id=$1 AND metric='storage' AND period=date '1970-01-01'",
        [org],
      )
    ).rows[0];
    if (Number(existing?.quantity ?? 0) + amount < 0)
      throw new ApiError(
        400,
        "INVALID_USAGE",
        "Storage release exceeds retained bytes",
      );
  }
  await db.query(
    "INSERT INTO usage(org_id,period,metric,quantity) VALUES($1,CASE WHEN $2='storage' THEN date '1970-01-01' ELSE date_trunc('month',now() AT TIME ZONE 'UTC')::date END,$2,0) ON CONFLICT DO NOTHING",
    [org, metric],
  );
  const usage = (
    await db.query(
      "UPDATE usage SET quantity=quantity+$3 WHERE org_id=$1 AND metric=$2 AND period=CASE WHEN $2='storage' THEN date '1970-01-01' ELSE date_trunc('month',now() AT TIME ZONE 'UTC')::date END RETURNING quantity",
      [org, metric, amount],
    )
  ).rows[0];
  if (Number(usage.quantity) > limit && !(metric === "storage" && amount < 0))
    throw new ApiError(429, "QUOTA_EXCEEDED", `${metric} quota exceeded`);
  return { quantity: Number(usage.quantity) };
}
export async function audit(
  db: pg.PoolClient,
  org: string,
  user: string | null,
  event: string,
  requestId: string,
  ip: string,
  result = "success",
) {
  await db.query(
    "INSERT INTO audit_logs(org_id,actor_id,event,request_id,ip,result) VALUES($1,$2,$3,$4,$5,$6)",
    [org, user, event, requestId, ip, result],
  );
}
