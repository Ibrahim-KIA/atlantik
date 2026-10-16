import { validateRuntime } from "./config.js";
import { pool, workerPool } from "./db.js";
import { scheduleTick } from "./jobs.js";
import { setTimeout as wait } from "node:timers/promises";
await validateRuntime();
const shutdown = new AbortController();
let running = true;
for (const s of ["SIGTERM", "SIGINT"])
  process.on(s, () => {
    running = false;
    shutdown.abort();
  });
while (running) {
  try {
    await scheduleTick();
  } catch {
    console.error(
      JSON.stringify({
        level: "error",
        message: "Scheduler failure; retry next interval",
      }),
    );
  }
  await wait(30000, undefined, { signal: shutdown.signal }).catch(() => {});
}
await workerPool.end();
await pool.end();
