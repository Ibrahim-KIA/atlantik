import { randomBytes, scrypt, timingSafeEqual, createHash } from "node:crypto";
export const secret = () => randomBytes(32).toString("base64url");
export const digest = (value: string) =>
  createHash("sha256").update(value).digest("hex");
const derive = (password: string, salt: string) =>
  new Promise<Buffer>((resolve, reject) =>
    scrypt(
      password,
      salt,
      64,
      { N: 65536, r: 8, p: 2, maxmem: 96 * 1024 * 1024 },
      (err, key) => (err ? reject(err) : resolve(key)),
    ),
  );
export async function hashPassword(password: string) {
  const salt = secret();
  return `${salt}:${(await derive(password, salt)).toString("hex")}`;
}
export async function verifyPassword(password: string, hash: string) {
  const [salt, value] = hash.split(":");
  const expected = Buffer.from(value, "hex");
  const actual = await derive(password, salt);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
export const permissions: Record<string, string[]> = {
  owner: [
    "organization.manage",
    "organization.delete",
    "ownership.transfer",
    "roles.manage",
    "webhooks.manage",
    "usage.write",
    "users.read",
    "users.create",
    "users.update",
    "users.delete",
    "teams.read",
    "teams.create",
    "teams.delete",
    "workspaces.read",
    "workspaces.create",
    "workspaces.manage",
    "billing.read",
    "billing.manage",
    "keys.manage",
    "audit.read",
  ],
  admin: [
    "organization.manage",
    "usage.write",
    "users.read",
    "users.create",
    "users.update",
    "users.delete",
    "teams.read",
    "teams.create",
    "teams.delete",
    "workspaces.read",
    "workspaces.create",
    "workspaces.manage",
    "billing.read",
  ],
  member: ["workspaces.read"],
};
export const plans = {
  free: { users: 5, workspaces: 3, requests: 10000, storage: 1073741824 },
  pro: { users: 50, workspaces: 25, requests: 500000, storage: 53687091200 },
};
export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}
export function requirePermission(scopes: string[], permission: string) {
  if (!scopes.includes(permission))
    throw new ApiError(403, "FORBIDDEN", "Permission denied");
}
