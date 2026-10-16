import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
const exec = promisify(execFile);
const api = `http://localhost:${process.env.HTTP_PORT ?? 8080}`;
const email = `smoke-${randomUUID()}@example.test`;
async function request(
  method: string,
  path: string,
  body?: unknown,
  token?: string,
  org?: string,
) {
  const response = await fetch(api + path, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(org ? { "x-organization-id": org } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  return { status: response.status, body: (await response.json()) as any };
}
async function mail() {
  const response = await fetch("http://localhost:8025/api/v1/messages");
  const data = (await response.json()) as any;
  return data.messages?.find(
    (m: any) =>
      m.To?.some((to: any) => to.Address === email) &&
      m.Subject === "Atlantik verify",
  );
}
assert.equal((await request("GET", "/health/ready")).status, 200);
let account: any;
try {
  await exec("docker", ["stop", "-t", "2", "atlantik-worker-1"]);
  account = await request("POST", "/api/v1/auth/register", {
    name: "Smoke",
    email,
    password: "smoke acceptance password",
    organization: "Smoke",
    slug: `smoke-${randomUUID()}`,
  });
  assert.equal(account.status, 201);
  assert.equal(
    (
      await request("POST", "/api/v1/auth/login", {
        email,
        password: "smoke acceptance password",
      })
    ).status,
    401,
  );
  assert.equal(
    await mail(),
    undefined,
    "Email must remain queued while worker is stopped",
  );
} finally {
  await exec("docker", ["start", "atlantik-worker-1"]);
}
let message: any;
for (let i = 0; i < 100; i++) {
  message = await mail();
  if (message) break;
  await new Promise((r) => setTimeout(r, 300));
}
assert.ok(message, "Queued email must be delivered after worker restart");
const text = (await (
  await fetch(`http://localhost:8025/api/v1/message/${message.ID}`)
).json()) as any;
const token = text.Text.trim().split(": ").at(-1);
assert.equal(
  (await request("POST", "/api/v1/auth/verify", { token })).status,
  200,
);
const login = await request("POST", "/api/v1/auth/login", {
  email,
  password: "smoke acceptance password",
});
assert.equal(login.status, 200);
const org = account.body.organizationId;
const session = login.body.token;
const workspace = await request(
  "POST",
  "/api/v1/workspaces",
  { name: "smoke workspace" },
  session,
  org,
);
assert.equal(workspace.status, 200);
assert.equal(
  (
    await request(
      "GET",
      `/api/v1/workspaces/${workspace.body.id}`,
      undefined,
      session,
      org,
    )
  ).status,
  200,
);
await exec("docker", ["restart", "-t", "2", "atlantik-api-1"]);
let ready = false;
for (let i = 0; i < 60; i++) {
  try {
    if ((await request("GET", "/health/ready")).status === 200) {
      ready = true;
      break;
    }
  } catch {}
  await new Promise((r) => setTimeout(r, 300));
}
assert.ok(ready);
assert.equal(
  (
    await request(
      "GET",
      `/api/v1/workspaces/${workspace.body.id}`,
      undefined,
      session,
      org,
    )
  ).status,
  200,
  "Session and tenant data survive API restart",
);
const spec = await request("GET", "/openapi.json");
assert.equal(spec.status, 200);
assert.equal(spec.body.info.title, "Atlantik API");
console.log(
  "Compose smoke passed: reverse proxy, registration, verification, real SMTP email, stopped/restarted worker, persistent sessions/workspaces, API restart and OpenAPI.",
);
