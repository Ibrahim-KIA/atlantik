import { test } from "node:test";
import assert from "node:assert/strict";
import {
  digest,
  secret,
  hashPassword,
  verifyPassword,
  requirePermission,
  permissions,
  plans,
} from "../src/core.js";
test("credentials are salted and wrong passwords fail", async () => {
  const a = await hashPassword("long secure password");
  const b = await hashPassword("long secure password");
  assert.notEqual(a, b);
  assert.ok(await verifyPassword("long secure password", a));
  assert.equal(await verifyPassword("wrong", a), false);
});
test("member and administrator privilege escalation denied", () => {
  assert.throws(() => requirePermission(permissions.member, "users.update"));
  assert.throws(() => requirePermission(permissions.admin, "billing.manage"));
  assert.throws(() => requirePermission(["workspaces.read"], "keys.manage"));
  requirePermission(permissions.owner, "billing.manage");
});
test("API secrets stored only as non-reversible digests", () => {
  const a = secret();
  assert.equal(digest(a).length, 64);
  assert.notEqual(digest(a), a);
  assert.notEqual(a, secret());
});
test("specified plan limits", () => {
  assert.equal(plans.free.users, 5);
  assert.equal(plans.free.workspaces, 3);
  assert.equal(plans.pro.requests, 500000);
});
