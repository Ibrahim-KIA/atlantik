import { validateRuntime } from "./config.js";
import { pool, workerPool } from "./db.js";
import { processOne, adapters } from "./jobs.js";
import { setTimeout as wait } from "node:timers/promises";
await validateRuntime();
const shutdown = new AbortController();
let running = true;
for (const s of ["SIGTERM", "SIGINT"])
  process.on(s, () => {
    running = false;
    shutdown.abort();
  });
const io = adapters();
while (running) {
  try {
    if (await processOne(io)) continue;
  } catch {
    console.error(
      JSON.stringify({ level: "error", message: "Worker dependency failure" }),
    );
  }
  await wait(1000, undefined, { signal: shutdown.signal }).catch(() => {});
}
await workerPool.end();
await pool.end();
