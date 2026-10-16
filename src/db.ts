import pg from "pg";
// Keep SQL dates as ISO calendar dates, independent of the host timezone.
pg.types.setTypeParser(1082, (value) => value);
export const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  connectionTimeoutMillis: 3000,
  statement_timeout: 5000,
});
export async function transaction<T>(
  org: string | undefined,
  fn: (db: pg.PoolClient) => Promise<T>,
  connectionPool: pg.Pool = pool,
): Promise<T> {
  const db = await connectionPool.connect();
  try {
    await db.query("BEGIN");
    if (org) await db.query("SELECT set_config('app.org_id',$1,true)", [org]);
    const result = await fn(db);
    await db.query("COMMIT");
    return result;
  } catch (e) {
    await db.query("ROLLBACK");
    throw e;
  } finally {
    db.release();
  }
}

export const workerPool = new pg.Pool({
  connectionString: process.env.WORKER_DATABASE_URL ?? process.env.DATABASE_URL,
  max: 4,
  connectionTimeoutMillis: 3000,
  statement_timeout: 5000,
});
export const workerTransaction = <T>(fn: (db: pg.PoolClient) => Promise<T>) =>
  transaction(undefined, fn, workerPool);

for (const connection of [pool, workerPool])
  connection.on("error", () =>
    console.error(
      JSON.stringify({ level: "error", message: "Database connection lost" }),
    ),
  );
