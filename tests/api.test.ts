import { test } from "node:test";
import assert from "node:assert/strict";
import { buildApp } from "../src/app.js";
import { pool } from "../src/db.js";
test("liveness, request IDs and predictable errors during dependency failure", async () => {
  const app = await buildApp();
  try {
    const live = await app.inject("/health/live");
    assert.equal(live.statusCode, 200);
    assert.equal(live.json().service, "Atlantik");
    assert.ok(live.headers["x-request-id"]);
    const missing = await app.inject("/unknown");
    assert.equal(missing.statusCode, 404);
    assert.ok(missing.json().requestId);
    const malformed = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      headers: { "content-type": "application/json" },
      payload: "{",
    });
    assert.equal(malformed.statusCode, 400);
    assert.equal(malformed.json().code, "INVALID_INPUT");
    assert.equal(malformed.headers["x-request-id"], malformed.json().requestId);
    const oversized = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      headers: { "content-type": "application/json" },
      payload: JSON.stringify({ password: "x".repeat(70000) }),
    });
    assert.equal(oversized.statusCode, 413);
    assert.ok(oversized.json().requestId);
    const ready = await app.inject("/health/ready");
    assert.equal(ready.statusCode, 503);
    assert.equal(ready.json().code, "SERVICE_UNAVAILABLE");
    assert.equal(ready.json().message, "Service unavailable");
  } finally {
    await app.close();
    await pool.end();
  }
});
