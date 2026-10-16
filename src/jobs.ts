import { randomUUID } from "node:crypto";
import nodemailer from "nodemailer";
import { workerTransaction } from "./db.js";
import { decrypt, deliverWebhook, signature } from "./security.js";
import { enqueue, event, notify, audit, limits } from "./services.js";
import type pg from "pg";
export type Adapters = {
  mail: (payload: any, id: string) => Promise<void>;
  webhook: typeof deliverWebhook;
};
export function adapters(): Adapters {
  const smtp = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT ?? 1025),
    secure: process.env.SMTP_SECURE === "true",
    connectionTimeout: 5000,
    socketTimeout: 5000,
    ...(process.env.SMTP_USER
      ? {
          auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASSWORD,
          },
        }
      : {}),
  });
  return {
    mail: async (payload, id) => {
      await smtp.sendMail({
        ...payload,
        from: process.env.EMAIL_FROM,
        messageId: `<${id}@atlantik>`,
      });
    },
    webhook: deliverWebhook,
  };
}
async function handle(db: pg.PoolClient, job: any, io: Adapters) {
  if (job.org_id)
    await db.query("SELECT set_config('app.org_id',$1,true)", [job.org_id]);
  const payload = decrypt<any>(job.payload.encrypted);
  if (job.type === "email") {
    await io.mail(payload, job.id);
    return;
  }
  if (job.type === "event") {
    const endpoints = (
      await db.query("SELECT id FROM webhooks WHERE org_id=$1 AND enabled", [
        job.org_id,
      ])
    ).rows;
    for (const w of endpoints) {
      const delivery = (
        await db.query(
          "INSERT INTO webhook_deliveries(org_id,webhook_id,event_id,status) VALUES($1,$2,$3,'pending') ON CONFLICT(org_id,webhook_id,event_id) DO NOTHING RETURNING id",
          [job.org_id, w.id, job.id],
        )
      ).rows[0];
      if (delivery)
        await enqueue(db, job.org_id, "webhook", {
          deliveryId: delivery.id,
          eventId: job.id,
          type: payload.type,
          data: payload.data,
        });
    }
    return;
  }
  if (job.type === "webhook") {
    const delivery = (
      await db.query(
        "SELECT d.*,w.url,w.secret,w.enabled FROM webhook_deliveries d JOIN webhooks w ON w.org_id=d.org_id AND w.id=d.webhook_id WHERE d.org_id=$1 AND d.id=$2 FOR UPDATE OF d",
        [job.org_id, payload.deliveryId],
      )
    ).rows[0];
    if (!delivery || ["delivered", "skipped"].includes(delivery.status)) return;
    if (!delivery.enabled) {
      await db.query(
        "UPDATE webhook_deliveries SET status='skipped',completed_at=now() WHERE org_id=$1 AND id=$2",
        [job.org_id, delivery.id],
      );
      return;
    }
    const timestamp = String(Math.floor(Date.now() / 1000));
    const body = JSON.stringify({
      id: payload.eventId,
      type: payload.type,
      data: payload.data,
    });
    const status = await io.webhook(delivery.url, body, {
      "x-atlantik-event-id": payload.eventId,
      "x-atlantik-timestamp": timestamp,
      "x-atlantik-signature": signature(
        decrypt<string>(delivery.secret),
        timestamp,
        body,
      ),
    });
    await db.query(
      "UPDATE webhook_deliveries SET status='delivered',attempts=$1,http_status=$2,completed_at=now(),last_error=NULL WHERE org_id=$3 AND id=$4",
      [job.attempts + 1, status, job.org_id, delivery.id],
    );
    return;
  }
  if (job.type === "billing") {
    const o = await limits(db, job.org_id);
    if (Number(o.subscription_version) >= payload.version) return;
    if (payload.plan) {
      const plan = await db.query("SELECT 1 FROM plans WHERE id=$1", [
        payload.plan,
      ]);
      if (!plan.rowCount) throw new Error("Unknown subscription plan");
    }
    const status =
      payload.type === "payment.failed"
        ? "PAST_DUE"
        : payload.type === "subscription.cancelled"
          ? "CANCELLED"
          : "ACTIVE";
    await db.query(
      "UPDATE organizations SET plan=coalesce($1,plan),subscription_status=$2,subscription_version=$3,renewal_at=CASE WHEN $2='ACTIVE' THEN now()+interval '1 month' ELSE renewal_at END WHERE id=$4",
      [payload.plan, status, payload.version, job.org_id],
    );
    await event(db, job.org_id, payload.type, { status, plan: payload.plan });
    await notify(db, job.org_id, payload.type, { status });
    await audit(db, job.org_id, null, payload.type, job.id, "worker");
    return;
  }
  if (job.type === "usage-report") {
    const usage = (
      await db.query(
        "SELECT metric,quantity,period FROM usage WHERE org_id=$1 ORDER BY period DESC LIMIT 100",
        [job.org_id],
      )
    ).rows;
    await notify(db, job.org_id, "usage.report", { usage });
    return;
  }
  throw new Error("Unsupported delivery adapter");
}
export async function processOne(io: Adapters = adapters()) {
  return workerTransaction(async (db) => {
    await db.query(
      "INSERT INTO service_heartbeats(name) VALUES('worker') ON CONFLICT(name) DO UPDATE SET updated_at=now()",
    );
    const job = (
      await db.query(
        "SELECT * FROM outbox WHERE completed_at IS NULL AND attempts<8 AND available_at<=now() ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1",
      )
    ).rows[0];
    if (!job) return false;
    await db.query("SAVEPOINT delivery");
    try {
      await handle(db, job, io);
      if (job.org_id)
        await db.query(
          "INSERT INTO usage(org_id,period,metric,quantity) VALUES($1,date_trunc('month',now() AT TIME ZONE 'UTC')::date,'jobs_completed',1) ON CONFLICT(org_id,period,metric) DO UPDATE SET quantity=usage.quantity+1",
          [job.org_id],
        );
      await db.query(
        "UPDATE outbox SET completed_at=now(),payload='{}',last_error=NULL WHERE id=$1",
        [job.id],
      );
    } catch {
      await db.query("ROLLBACK TO SAVEPOINT delivery");
      await db.query(
        "UPDATE outbox SET attempts=attempts+1,last_error='Delivery failed',available_at=now()+make_interval(secs=>LEAST(3600,power(2,attempts+1)::int)) WHERE id=$1",
        [job.id],
      );
      if (job.type === "webhook" && job.org_id) {
        await db.query("SELECT set_config('app.org_id',$1,true)", [job.org_id]);
        const p = decrypt<any>(job.payload.encrypted);
        await db.query(
          "UPDATE webhook_deliveries SET status=$1,attempts=$2,last_error='Delivery failed' WHERE org_id=$3 AND id=$4",
          [
            job.attempts >= 7 ? "failed" : "retrying",
            job.attempts + 1,
            job.org_id,
            p.deliveryId,
          ],
        );
      }
    }
    return true;
  });
}
export async function scheduleTick() {
  await workerTransaction(async (db) => {
    await db.query("SELECT pg_advisory_xact_lock(714240)");
    await db.query(
      "INSERT INTO service_heartbeats(name) VALUES('scheduler') ON CONFLICT(name) DO UPDATE SET updated_at=now()",
    );
    await db.query("DELETE FROM tokens WHERE expires_at<now()");
    await db.query("DELETE FROM sessions WHERE expires_at<now()");
    const orgs = (
      await db.query(
        "SELECT id,subscription_status,renewal_at FROM organizations WHERE status='ACTIVE' ORDER BY id",
      )
    ).rows;
    for (const org of orgs) {
      await db.query("SELECT set_config('app.org_id',$1,true)", [org.id]);
      if (
        ["TRIAL", "PAST_DUE", "ACTIVE"].includes(org.subscription_status) &&
        Date.parse(org.renewal_at) < Date.now()
      ) {
        await db.query(
          "UPDATE organizations SET subscription_status=$1 WHERE id=$2",
          [
            org.subscription_status === "ACTIVE" ? "PAST_DUE" : "SUSPENDED",
            org.id,
          ],
        );
        await notify(db, org.id, "subscription.expired", {
          status: org.subscription_status,
        });
        await audit(
          db,
          org.id,
          null,
          "subscription.expired",
          randomUUID(),
          "scheduler",
        );
      }
      if (Date.parse(org.renewal_at) < Date.now() + 3 * 86400000) {
        const r = await db.query(
          "INSERT INTO schedule_runs(name,period) VALUES($1,current_date::text) ON CONFLICT DO NOTHING RETURNING name",
          [`reminder:${org.id}`],
        );
        if (r.rowCount)
          await notify(db, org.id, "subscription.reminder", {
            renewalAt: org.renewal_at,
          });
      }
      const report = await db.query(
        "INSERT INTO schedule_runs(name,period) VALUES($1,to_char(now() AT TIME ZONE 'UTC','YYYY-MM')) ON CONFLICT DO NOTHING RETURNING name",
        [`report:${org.id}`],
      );
      if (report.rowCount) await enqueue(db, org.id, "usage-report", {});
      await db.query(
        "DELETE FROM invitations WHERE org_id=$1 AND expires_at<now() AND accepted_at IS NULL",
        [org.id],
      );
    }
  });
}
