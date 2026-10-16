import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  createHmac,
  timingSafeEqual,
} from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import https from "node:https";
import { ApiError } from "./core.js";
function key() {
  const value = Buffer.from(process.env.APP_ENCRYPTION_KEY ?? "", "base64");
  if (value.length !== 32)
    throw new Error("APP_ENCRYPTION_KEY must be a base64 32-byte key");
  return value;
}
export function encrypt(value: unknown): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(value), "utf8"),
    cipher.final(),
  ]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64");
}
export function decrypt<T>(value: string): T {
  const data = Buffer.from(value, "base64");
  const cipher = createDecipheriv("aes-256-gcm", key(), data.subarray(0, 12));
  cipher.setAuthTag(data.subarray(12, 28));
  return JSON.parse(
    Buffer.concat([cipher.update(data.subarray(28)), cipher.final()]).toString(
      "utf8",
    ),
  );
}
export function signature(secret: string, timestamp: string, body: string) {
  return createHmac("sha256", secret)
    .update(`${timestamp}.${body}`)
    .digest("hex");
}
export function validSignature(
  secret: string,
  timestamp: string,
  body: string,
  sig: string,
) {
  if (
    !/^\d+$/.test(timestamp) ||
    Math.abs(Date.now() / 1000 - Number(timestamp)) > 300 ||
    !/^[a-f0-9]{64}$/.test(sig)
  )
    return false;
  return timingSafeEqual(
    Buffer.from(signature(secret, timestamp, body), "hex"),
    Buffer.from(sig, "hex"),
  );
}
export function publicAddress(ip: string) {
  if (isIP(ip) === 4) {
    const [a, b] = ip.split(".").map(Number);
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a >= 224 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 192 && b === 0)
    );
  }
  return false;
}
// IPv4-only public delivery: pin the vetted DNS result in the TLS request to prevent rebinding.
export async function deliverWebhook(
  url: string,
  body: string,
  headers: Record<string, string>,
): Promise<number> {
  const target = new URL(url);
  if (
    target.protocol !== "https:" ||
    target.username ||
    target.password ||
    (target.port && target.port !== "443")
  )
    throw new Error("Unsafe webhook URL");
  let dnsTimer: ReturnType<typeof setTimeout> | undefined;
  const addresses = await Promise.race([
    lookup(target.hostname, { all: true, family: 4 }),
    new Promise<never>((_resolve, reject) => {
      dnsTimer = setTimeout(() => reject(new Error("DNS timeout")), 2000);
    }),
  ]).finally(() => clearTimeout(dnsTimer));
  if (!addresses.length || addresses.some((a) => !publicAddress(a.address)))
    throw new Error("Non-public webhook destination");
  const address = addresses[0].address;
  return new Promise((resolve, reject) => {
    const req = https.request(
      target,
      {
        method: "POST",
        headers: {
          ...headers,
          "content-type": "application/json",
          "content-length": String(Buffer.byteLength(body)),
        },
        lookup: (_host, _options, cb) => cb(null, address, 4),
      },
      (res) => {
        res.resume();
        const status = res.statusCode ?? 0;
        if (status >= 200 && status < 300) resolve(status);
        else reject(new Error(`HTTP ${status}`));
      },
    );
    const timeout = setTimeout(
      () => req.destroy(new Error("Webhook timeout")),
      5000,
    );
    req.on("close", () => clearTimeout(timeout));
    req.on("error", reject);
    req.end(body);
  });
}
export function webhookUrl(value: string) {
  const u = new URL(value);
  if (
    u.protocol !== "https:" ||
    u.username ||
    u.password ||
    (u.port && u.port !== "443") ||
    isIP(u.hostname) ||
    u.hostname === "localhost" ||
    u.hostname.endsWith(".localhost") ||
    u.hostname.endsWith(".local")
  )
    throw new ApiError(
      400,
      "UNSAFE_WEBHOOK",
      "Use a public HTTPS hostname on port 443",
    );
  return u.toString();
}
