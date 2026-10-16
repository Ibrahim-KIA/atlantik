import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { buildApp } from "../src/app.js";
import { pool, workerPool } from "../src/db.js";
const exec = promisify(execFile);
test(
  "actual database/cache outages fail closed and recover",
  { skip: process.env.RUN_DOCKER_FAILURE_TESTS !== "1" },
  async (t) => {
    const app = await buildApp();
    const recover = async () => {
      for (let i = 0; i < 30; i++) {
        if ((await app.inject("/health/ready")).statusCode === 200) return;
        await new Promise((r) => setTimeout(r, 200));
      }
      assert.fail("Dependencies did not recover");
    };
    try {
      await recover();
      for (const [name, label] of [
        ["atlantik-test-db", "database"],
        ["atlantik-test-redis", "cache"],
      ])
        await t.test(`${label} stop/restart`, async () => {
          try {
            await exec("docker", ["stop", "-t", "1", name]);
            assert.equal((await app.inject("/health/live")).statusCode, 200);
            assert.equal((await app.inject("/health/ready")).statusCode, 503);
            const login = await app.inject({
              method: "POST",
              url: "/api/v1/auth/login",
              payload: {
                email: "nobody@example.test",
                password: "any-password",
              },
            });
            assert.equal(login.statusCode, 503);
            assert.ok(login.json().requestId);
            assert.equal(login.headers["x-request-id"], login.json().requestId);
            assert.ok(!login.body.includes("postgresql"));
          } finally {
            await exec("docker", ["start", name]);
            await recover();
          }
        });
    } finally {
      await app.close();
      await pool.end();
      await workerPool.end();
    }
  },
);
