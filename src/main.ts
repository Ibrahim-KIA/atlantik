import { validateRuntime } from "./config.js";
import { buildApp } from "./app.js";
import { pool } from "./db.js";
if (!process.env.DATABASE_URL || !process.env.REDIS_URL)
  throw new Error("DATABASE_URL and REDIS_URL required");
await validateRuntime();
const app = await buildApp();
await app.listen({ port: Number(process.env.PORT ?? 3000), host: "0.0.0.0" });
for (const signal of ["SIGINT", "SIGTERM"])
  process.on(signal, async () => {
    await app.close();
    await pool.end();
    process.exit(0);
  });
