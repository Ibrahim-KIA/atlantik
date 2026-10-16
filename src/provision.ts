// Run only with the migration credential. Values are parameterized/escaped, never logged.
import { pool, transaction } from "./db.js";
export async function provision() {
  await transaction(undefined, async (db) => {
    for (const role of ["atlantik_app", "atlantik_worker"]) {
      const password =
        process.env[
          role === "atlantik_app" ? "APP_DB_PASSWORD" : "WORKER_DB_PASSWORD"
        ];
      if (!password || password.length < 24)
        throw new Error(
          "Database role passwords of at least 24 characters required",
        );
      const exists = await db.query("SELECT 1 FROM pg_roles WHERE rolname=$1", [
        role,
      ]);
      if (!exists.rowCount)
        await db.query(
          `CREATE ROLE ${role} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE`,
        );
      await db.query(
        `ALTER ROLE ${role} PASSWORD ${db.escapeLiteral(password)}`,
      );
      await db.query(`ALTER ROLE ${role} SET timezone='UTC'`);
    }
    await db.query("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC");
    await db.query(
      "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM atlantik_app,atlantik_worker",
    );
    await db.query(
      "GRANT USAGE ON SCHEMA public TO atlantik_app,atlantik_worker",
    );
    await db.query(
      "GRANT SELECT,INSERT,UPDATE,DELETE ON sessions,tokens,organizations,memberships,workspaces,workspace_members,teams,team_members,api_keys,usage,billing_events,notifications,webhooks,webhook_deliveries,roles,invitations,workspace_teams,usage_events,platform_config TO atlantik_app",
    );
    await db.query(
      "GRANT EXECUTE ON FUNCTION account_organizations(text),platform_organizations(text),platform_organization_status(text,uuid,text),platform_statistics(text) TO atlantik_app",
    );
    await db.query("GRANT SELECT ON service_heartbeats TO atlantik_app");
    await db.query(
      "GRANT SELECT,INSERT,UPDATE ON service_heartbeats TO atlantik_worker",
    );
    await db.query("GRANT SELECT ON plans TO atlantik_app,atlantik_worker");
    await db.query(
      "GRANT SELECT,INSERT ON audit_logs,platform_audit TO atlantik_app,atlantik_worker",
    );
    await db.query("GRANT INSERT ON outbox TO atlantik_app");
    await db.query(
      "GRANT SELECT(id,type,attempts,available_at,completed_at) ON outbox TO atlantik_app",
    );
    await db.query(
      "GRANT SELECT,INSERT,UPDATE ON outbox,webhook_deliveries,notifications,schedule_runs TO atlantik_worker",
    );
    await db.query("GRANT SELECT,INSERT,UPDATE ON usage TO atlantik_worker");
    await db.query(
      "GRANT SELECT ON webhooks,memberships,billing_events TO atlantik_worker",
    );
    await db.query("GRANT SELECT(id,email) ON users TO atlantik_worker");
    await db.query("GRANT SELECT ON users TO atlantik_app");
    await db.query(
      "GRANT INSERT(name,email,password,status),UPDATE(name,email,password,status) ON users TO atlantik_app",
    );
    await db.query(
      "GRANT SELECT(id,status,plan,subscription_status,subscription_started_at,subscription_version,renewal_at),UPDATE(plan,subscription_status,subscription_version,renewal_at) ON organizations TO atlantik_worker",
    );
    await db.query(
      "GRANT SELECT,DELETE ON tokens,sessions,invitations TO atlantik_worker",
    );
  });
}
