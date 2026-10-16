import { readFile, readdir } from "node:fs/promises";
import { provision } from "./provision.js";
import { pool, transaction } from "./db.js";
await transaction(undefined, async (db) => {
  await db.query("SELECT pg_advisory_xact_lock(714239)");
  await db.query(
    "CREATE TABLE IF NOT EXISTS migrations(name text PRIMARY KEY, applied_at timestamptz DEFAULT now())",
  );
  for (const name of (await readdir("migrations")).sort()) {
    if (
      (await db.query("SELECT 1 FROM migrations WHERE name=$1", [name]))
        .rowCount
    )
      continue;
    await db.query(await readFile(`migrations/${name}`, "utf8"));
    await db.query("INSERT INTO migrations(name) VALUES($1)", [name]);
  }
});
if (process.env.APP_DB_PASSWORD && process.env.WORKER_DB_PASSWORD)
  await provision();
await pool.end();
