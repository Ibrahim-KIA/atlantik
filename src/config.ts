import { pool } from "./db.js";
export async function validateRuntime() {
  for (const key of ["DATABASE_URL", "APP_ENCRYPTION_KEY"])
    if (!process.env[key]) throw new Error(`${key} required`);
  if (Buffer.from(process.env.APP_ENCRYPTION_KEY!, "base64").length !== 32)
    throw new Error("Encryption key must contain 32 bytes");
  const role = (
    await pool.query(
      "SELECT r.rolsuper,r.rolbypassrls,exists(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tableowner=current_user) AS owns_tables FROM pg_roles r WHERE rolname=current_user",
    )
  ).rows[0];
  if (role.rolsuper || role.rolbypassrls || role.owns_tables)
    throw new Error("Use a restricted runtime role, never the migration role");
  if (
    !["development", "testing", "staging", "production"].includes(
      process.env.APP_ENV ?? "development",
    )
  )
    throw new Error("Invalid APP_ENV");
  if (["production", "staging"].includes(process.env.APP_ENV ?? "")) {
    if (process.env.BILLING_MODE === "simulation")
      throw new Error(
        "Billing simulation is forbidden outside development/testing",
      );
    for (const key of ["BILLING_WEBHOOK_SECRET", "SMTP_HOST", "EMAIL_FROM"])
      if (!process.env[key]) throw new Error(`${key} required`);
  }
}
