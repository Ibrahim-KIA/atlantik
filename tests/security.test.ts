import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  encrypt,
  decrypt,
  signature,
  validSignature,
  publicAddress,
  webhookUrl,
  deliverWebhook,
} from "../src/security.js";
process.env.APP_ENCRYPTION_KEY = randomBytes(32).toString("base64");
test("encrypted payloads authenticate ciphertext and use unique nonces", () => {
  const a = encrypt({ token: "private" });
  assert.notEqual(a, encrypt({ token: "private" }));
  assert.deepEqual(decrypt(a), { token: "private" });
  const tampered = Buffer.from(a, "base64");
  tampered[30] ^= 1;
  assert.throws(() => decrypt(tampered.toString("base64")));
});
test("signature replay window, tampering, malformed signatures", () => {
  const ts = String(Math.floor(Date.now() / 1000));
  const sig = signature("test-only-secret", ts, "body");
  assert.ok(validSignature("test-only-secret", ts, "body", sig));
  assert.equal(validSignature("test-only-secret", ts, "changed", sig), false);
  assert.equal(validSignature("test-only-secret", "1", "body", sig), false);
  assert.equal(validSignature("test-only-secret", ts, "body", "bad"), false);
});
test("webhooks reject unsafe addresses and redirect destinations", async () => {
  for (const ip of [
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "169.254.169.254",
    "192.168.1.1",
    "100.64.1.2",
    "0.0.0.0",
    "::1",
    "::ffff:127.0.0.1",
    "224.0.0.1",
  ])
    assert.equal(publicAddress(ip), false, ip);
  assert.ok(publicAddress("8.8.8.8"));
  for (const url of [
    "http://example.com",
    "https://localhost",
    "https://127.0.0.1",
    "https://user:pass@example.com",
    "https://example.com:8080",
  ])
    assert.throws(() => webhookUrl(url));
  await assert.rejects(
    deliverWebhook("https://localhost/", "{}", {}),
    /Non-public/,
  );
});
