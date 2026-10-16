import { readFileSync, writeFileSync } from "node:fs";
import { format } from "prettier";
const str = { type: "string" },
  id = { type: "string", format: "uuid" },
  email = { type: "string", format: "email" },
  pass = { type: "string", minLength: 12, maxLength: 128 },
  name = { type: "string", minLength: 1, maxLength: 100 },
  date = { type: "string", format: "date-time" },
  bool = { type: "boolean" };
const object = (
  properties: Record<string, unknown>,
  required = Object.keys(properties),
) => ({ type: "object", properties, required, additionalProperties: false });
const arr = (items: unknown) => ({ type: "array", items });
const en = (...values: string[]) => ({ type: "string", enum: values });
const role = en("admin", "member");
const bodies: Record<string, unknown> = {
  "POST /api/v1/auth/register": object({
    name,
    email,
    password: pass,
    organization: name,
    slug: { type: "string", pattern: "^[a-z0-9-]{3,60}$" },
  }),
  "POST /api/v1/auth/login": object({
    email,
    password: { type: "string", maxLength: 128 },
  }),
  "POST /api/v1/auth/verify": object({ token: str }),
  "POST /api/v1/auth/password-reset/request": object({ email }),
  "POST /api/v1/auth/password-reset/confirm": object({
    token: str,
    password: pass,
  }),
  "POST /api/v1/auth/verification/resend": object({ email }),
  "POST /api/v1/auth/password/change": object({
    currentPassword: str,
    password: pass,
  }),
  "POST /api/v1/auth/email/change": object({ email, password: str }),
  "PATCH /api/v1/me": object({ name }),
  "POST /api/v1/organizations": object({
    name,
    slug: { type: "string", pattern: "^[a-z0-9-]{3,60}$" },
  }),
  "PATCH /api/v1/organization": object(
    {
      name,
      settings: {
        type: "object",
        additionalProperties: { type: ["string", "number", "boolean", "null"] },
      },
    },
    [],
  ),
  "POST /api/v1/organization/transfer": object({ userId: id, password: str }),
  "POST /api/v1/invitations": object({ email, role }, ["email"]),
  "POST /api/v1/invitations/accept": object({ organizationId: id, token: str }),
  "PATCH /api/v1/users/:id/role": object({ role }),
  "POST /api/v1/roles": object({ name, permissions: arr(str) }),
  "PATCH /api/v1/roles/:id": object({ permissions: arr(str) }),
  "PUT /api/v1/users/:id/custom-role": object({ roleId: id }),
  "POST /api/v1/teams": object({ name }),
  "POST /api/v1/workspaces": object({ name }),
  "PATCH /api/v1/workspaces/:id": object({ name }),
  "POST /api/v1/api-keys": object({
    name,
    scopes: arr(
      en(
        "workspaces.read",
        "workspaces.create",
        "workspaces.manage",
        "teams.read",
      ),
    ),
    expiresAt: date,
  }),
  "PATCH /api/v1/subscription": object({
    plan: en("free", "pro"),
    status: en("ACTIVE", "CANCELLED"),
  }),
  "POST /api/v1/usage/events": object({
    eventId: { type: "string", minLength: 1, maxLength: 100 },
    metric: en("storage", "jobs", "bandwidth"),
    quantity: {
      type: "integer",
      minimum: -Number.MAX_SAFE_INTEGER,
      maximum: Number.MAX_SAFE_INTEGER,
      not: { const: 0 },
      description:
        "Negative quantities are accepted only for storage releases.",
    },
  }),
  "POST /api/v1/webhooks": object({
    url: { type: "string", format: "uri", maxLength: 2048 },
  }),
  "PATCH /api/v1/webhooks/:id": object({ enabled: bool }),
  "PATCH /api/v1/platform/organizations/:id/status": object({
    status: en("ACTIVE", "SUSPENDED", "PENDING", "DELETED"),
  }),
  "PATCH /api/v1/platform/users/:id/status": object({
    status: en("ACTIVE", "SUSPENDED", "DEACTIVATED"),
  }),
  "PUT /api/v1/platform/config/:key": object({ value: bool }),
  "POST /api/v1/billing/events": object(
    {
      id: str,
      organizationId: id,
      type: en(
        "subscription.created",
        "subscription.updated",
        "subscription.cancelled",
        "payment.succeeded",
        "payment.failed",
      ),
      version: { type: "integer", minimum: 1 },
      plan: str,
    },
    ["id", "organizationId", "type", "version"],
  ),
};
const descriptions: Record<string, string> = {
  "/api/v1/auth/register":
    "Create an unverified account and organization atomically; send verification email asynchronously.",
  "/api/v1/auth/login":
    "Issue an opaque 24-hour session for an active, verified user. Rate limited by client IP and normalized account digest.",
  "/api/v1/auth/logout":
    "Revoke the current device session, even when its organization is suspended.",
  "/api/v1/auth/verify": "Consume a one-hour, single-use verification token.",
  "/api/v1/auth/password-reset/request":
    "Always return accepted; eligible users receive a one-hour token. Repeated requests invalidate earlier tokens.",
  "/api/v1/auth/password-reset/confirm":
    "Consume a reset token, change password, revoke all device sessions, and notify the account.",
  "/api/v1/auth/email/change":
    "Require current password, change email, suspend protected access until verification, and revoke sessions/tokens.",
  "/api/v1/organization/transfer":
    "Owner only; current password required; target must be an active member. Transfer atomically.",
  "/api/v1/subscription":
    "Owner changes require development/testing simulation mode. Provider mode returns BILLING_PROVIDER_REQUIRED. Read allowed to administrators.",
  "/api/v1/billing/events":
    "HMAC-SHA256 over timestamp + dot + exact JSON bytes. Five-minute acceptance window; globally unique event ID; monotonically increasing per-organization version. Queue processing is asynchronous.",
  "/api/v1/webhooks":
    "Owner manages public HTTPS endpoints. Signing secret returned once; encrypted at rest. No redirects, private addresses, credentials or nonstandard ports.",
  "/api/v1/api-keys":
    "Owner creates named, scoped credentials with future expiration. Secret returned once; metadata excludes digests. Keys cannot manage billing or memberships.",
  "/api/v1/reports/usage":
    "Enqueue a usage report to the owner, enforcing the client job budget.",
  "/api/v1/usage/events":
    "Owner/admin-controlled usage ingestion. Stable event ID prevents duplicate charges. System integrations must use trusted accounting data.",
  "/api/v1/workspaces/:id":
    "Workspace access requires organization permission plus direct/team membership, or organization-wide management permission. Authorized scoped API keys may read organization workspaces.",
  "/api/v1/platform/organizations":
    "Platform metadata only. Platform sessions do not gain customer resource access.",
  "/api/v1/platform/health":
    "Dependency health, worker/scheduler heartbeat timestamps, and per-route request/error/latency aggregates. No customer payloads.",
};
const stamp = { type: ["string", "null"], format: "date-time" };
const entity = object({ id, name });
const workspace = object({ id, name, created_at: date });
const keyMeta = object({
  id,
  name,
  scopes: arr(str),
  expires_at: date,
  revoked_at: stamp,
  last_used: stamp,
  created_at: date,
  status: en("ACTIVE", "EXPIRED", "REVOKED"),
});
const keySecret = object({
  id,
  name,
  scopes: arr(str),
  expires_at: date,
  secret: str,
});
const updated = object({ updated: bool });
function responseSchema(method: string, url: string): unknown {
  const key = `${method.toUpperCase()} ${url}`;
  const exact: Record<string, unknown> = {
    "POST /api/v1/auth/register": object({ userId: id, organizationId: id }),
    "POST /api/v1/auth/login": object({
      token: str,
      expiresIn: { type: "integer", const: 86400 },
    }),
    "POST /api/v1/auth/verify": object({ verified: bool }),
    "GET /api/v1/me": object({ id, name, email }),
    "GET /api/v1/auth/sessions": arr(
      object({
        id,
        created_at: date,
        expires_at: date,
        ip: { type: ["string", "null"] },
        user_agent: { type: ["string", "null"] },
      }),
    ),
    "GET /api/v1/organization": object({
      id,
      name,
      slug: str,
      status: str,
      plan: str,
      subscription_status: str,
      renewal_at: date,
      settings: { type: "object" },
      owner_id: id,
      created_at: date,
      last_activity: date,
    }),
    "POST /api/v1/organizations": object({ id, name, slug: str }),
    "GET /api/v1/users": arr(object({ id, name, email, role: str })),
    "POST /api/v1/invitations": object({ id, email, role, expires_at: date }),
    "GET /api/v1/invitations": arr(
      object({ id, email, role, expires_at: date, accepted_at: stamp }),
    ),
    "GET /api/v1/roles": object({
      builtIn: { type: "object", additionalProperties: arr(str) },
      custom: arr(object({ id, name, permissions: arr(str) })),
    }),
    "POST /api/v1/roles": object({ id, name, permissions: arr(str) }),
    "GET /api/v1/teams": arr(entity),
    "GET /api/v1/organizations": arr(
      object({ id, name, slug: str, status: str, role: str }),
    ),
    "POST /api/v1/teams": entity,
    "GET /api/v1/teams/:id/members": arr(entity),
    "GET /api/v1/workspaces": arr(workspace),
    "GET /api/v1/workspaces/:id": workspace,
    "POST /api/v1/workspaces": entity,
    "PATCH /api/v1/workspaces/:id": entity,
    "GET /api/v1/api-keys": arr(keyMeta),
    "POST /api/v1/api-keys": keySecret,
    "POST /api/v1/api-keys/:id/rotate": keySecret,
    "GET /api/v1/plans": arr(
      object({
        id: str,
        limits: { type: "object", additionalProperties: { type: "integer" } },
      }),
    ),
    "GET /api/v1/subscription": object({
      plan: str,
      status: str,
      startedAt: date,
      renewalAt: date,
      limits: { type: "object" },
    }),
    "GET /api/v1/usage": arr(
      object({
        period: { type: "string", format: "date" },
        metric: str,
        quantity: { type: "string", description: "PostgreSQL bigint string" },
      }),
    ),
    "POST /api/v1/usage/events": {
      oneOf: [
        object({ quantity: { type: "integer" } }),
        object({ duplicate: bool }),
      ],
    },
    "GET /api/v1/audit-logs": arr(
      object({
        actor_id: { type: ["string", "null"], format: "uuid" },
        event: str,
        request_id: str,
        ip: str,
        result: str,
        created_at: date,
      }),
    ),
    "GET /api/v1/notifications": arr(
      object({
        id,
        type: str,
        payload: { type: "object" },
        read_at: stamp,
        created_at: date,
      }),
    ),
    "POST /api/v1/webhooks": object({
      id,
      url: str,
      enabled: bool,
      created_at: date,
      secret: str,
    }),
    "GET /api/v1/webhooks": arr(
      object({ id, url: str, enabled: bool, created_at: date }),
    ),
    "GET /api/v1/webhook-deliveries": arr(
      object({
        id,
        webhook_id: id,
        event_id: id,
        status: str,
        attempts: { type: "integer" },
        http_status: { type: ["integer", "null"] },
        last_error: { type: ["string", "null"] },
        created_at: date,
        completed_at: stamp,
      }),
    ),
    "GET /api/v1/platform/organizations": arr(
      object({
        id,
        name,
        slug: str,
        status: str,
        plan: str,
        subscription_status: str,
        created_at: date,
      }),
    ),
    "GET /api/v1/platform/audit-logs": arr(
      object({
        actor_id: { type: ["string", "null"] },
        event: str,
        request_id: str,
        ip: str,
        result: str,
        created_at: date,
      }),
    ),
    "GET /api/v1/platform/config": arr(
      object({ key: str, value: bool, updated_at: date }),
    ),
    "POST /api/v1/billing/events": object({ accepted: bool, duplicate: bool }, [
      "accepted",
    ]),
  };
  if (exact[key]) return exact[key];
  if (url === "/health/live")
    return object({
      status: { const: "alive" },
      service: { const: "Atlantik" },
    });
  if (url === "/health/ready") return object({ status: { const: "ready" } });
  if (
    url === "/openapi.json" ||
    url.includes("/platform/health") ||
    url.includes("/platform/statistics")
  )
    return { type: "object", additionalProperties: true };
  if (method === "delete")
    return object({
      [url.includes("/sessions/") || url.includes("/api-keys/")
        ? "revoked"
        : url.includes("/members/") ||
            url.includes("/teams/:teamId") ||
            url.includes("/users/")
          ? "removed"
          : "deleted"]: bool,
    });
  if (
    (method === "put" && url.includes("/members/")) ||
    (method === "put" && url.includes("/teams/:teamId"))
  )
    return object({ added: bool });
  if (method === "patch" || method === "put") return updated;
  if (url.endsWith("/transfer")) return object({ transferred: bool });
  if (url.endsWith("/logout")) return object({ revoked: bool });
  if (url.endsWith("/password/change"))
    return object({ changed: bool, reauthenticationRequired: bool });
  if (url.endsWith("/password-reset/confirm")) return object({ changed: bool });
  if (url.endsWith("/email/change"))
    return object({ verificationRequired: bool });
  return object({ accepted: bool });
}
const paths: Record<string, any> = {};
const rows: string[] = [];
for (const file of ["src/app.ts", "src/features.ts"]) {
  const source = readFileSync(file, "utf8");
  for (const m of source.matchAll(
    /\b(?:app|scope)\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]/g,
  )) {
    const method = m[1],
      url = m[2],
      key = `${method.toUpperCase()} ${url}`,
      path = url.replace(/:([A-Za-z]+)/g, "{$1}");
    const publicRoute =
      url.startsWith("/health/") ||
      url === "/openapi.json" ||
      [
        "/api/v1/auth/register",
        "/api/v1/auth/login",
        "/api/v1/auth/verify",
        "/api/v1/auth/password-reset/request",
        "/api/v1/auth/password-reset/confirm",
        "/api/v1/auth/verification/resend",
      ].includes(url);
    const signed = url === "/api/v1/billing/events";
    const session =
      url.startsWith("/api/v1/auth/") ||
      url === "/api/v1/me" ||
      url === "/api/v1/organizations" ||
      url === "/api/v1/invitations/accept" ||
      url === "/api/v1/plans" ||
      url.startsWith("/api/v1/platform/");
    const tenant = !publicRoute && !signed && !session;
    const params: any[] = [];
    for (const p of url.matchAll(/:([A-Za-z]+)/g))
      params.push({
        name: p[1],
        in: "path",
        required: true,
        schema: p[1] === "key" ? en("maintenance", "signupEnabled") : id,
      });
    if (tenant)
      params.push({
        name: "X-Organization-Id",
        in: "header",
        required: true,
        schema: id,
      });
    if (signed) {
      params.push(
        {
          name: "X-Atlantik-Timestamp",
          in: "header",
          required: true,
          schema: str,
        },
        {
          name: "X-Atlantik-Signature",
          in: "header",
          required: true,
          schema: str,
        },
      );
    }
    const snippet = source.slice(m.index!, m.index! + 250);
    const permission = snippet.match(
      /tenant\(\s*req,\s*['"]([^'"]+)['"]/s,
    )?.[1];
    const description =
      descriptions[url] ??
      `${method.toUpperCase()} ${url}. ${tenant ? "Organization-scoped operation; resource identifiers are checked within the selected tenant." : session ? "Requires an active user session." : "Returns service metadata."}`;
    const responses: any = {};
    responses[url === "/api/v1/auth/register" ? "201" : "200"] = {
      description:
        "Successful JSON response. Entity fields use database snake_case; credential/envelope fields use camelCase.",
      headers: { "X-Request-Id": { schema: str } },
      content: {
        "application/json": { schema: responseSchema(method, url) },
      },
    };
    for (const code of [
      "400",
      "401",
      "403",
      "404",
      "409",
      "413",
      "415",
      "429",
      "503",
    ])
      responses[code] = {
        description: (
          {
            "400": "Invalid input or expired single-use token",
            "401": "Invalid, revoked or expired credential",
            "403":
              "Insufficient permission or inactive account/organization/subscription",
            "404": "Resource absent or hidden by tenant/resource authorization",
            "409": "Conflict or resource-count quota exceeded",
            "413": "Request body exceeds 64 KiB",
            "415": "Unsupported content type",
            "429": "Rate or monthly quota exceeded",
            "503": "Dependency failure or maintenance",
          } as any
        )[code],
        content: {
          "application/json": {
            schema: { $ref: "#/components/schemas/Error" },
          },
        },
      };
    const op: any = {
      operationId: `${method}_${url.replace(/[^a-zA-Z0-9]+/g, "_")}`,
      summary: key,
      description:
        description +
        (permission ? ` Required permission: ${permission}.` : ""),
      parameters: params,
      security: publicRoute
        ? []
        : signed
          ? [{ billingSignature: [] }]
          : [{ bearerAuth: [] }],
      responses,
    };
    if (bodies[key])
      op.requestBody = {
        required: true,
        content: { "application/json": { schema: bodies[key] } },
      };
    (paths[path] ??= {})[method] = op;
    rows.push(
      `|${method.toUpperCase()}|\`${url}\`|${publicRoute ? "Public" : signed ? "Provider signature" : tenant ? "Tenant + " + (permission ?? "permission") : "Session" + (url.includes("/platform/") ? " + platform admin" : "")}|${bodies[key] ? "See OpenAPI request schema" : "No JSON body"}|`,
    );
  }
}
const spec = {
  openapi: "3.1.0",
  info: {
    title: "Atlantik API",
    version: "1.0.0",
    description:
      "Multi-tenant SaaS backend. Lists are capped at 100 rows. See API.md for lifecycle, scopes, errors and accounting semantics.",
  },
  servers: [{ url: "http://localhost:8080", description: "Local development" }],
  paths,
  components: {
    securitySchemes: {
      bearerAuth: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "Opaque session or atk_ API key",
      },
      billingSignature: {
        type: "apiKey",
        in: "header",
        name: "X-Atlantik-Signature",
      },
    },
    schemas: {
      Error: object({
        code: str,
        message: str,
        details: { type: "array", items: {} },
        requestId: str,
      }),
    },
  },
};
writeFileSync("docs/openapi.json", JSON.stringify(spec, null, 2) + "\n");
writeFileSync(
  "docs/endpoints.md",
  await format(
    "# Atlantik endpoint catalog\n\nGenerated by `npm run docs:api`. Request-body constraints and response/error envelopes are in [OpenAPI](openapi.json).\n\n|Method|Path|Authorization|Body|\n|---|---|---|---|\n" +
      rows.join("\n") +
      "\n",
    { parser: "markdown" },
  ),
);
console.log(`Documented ${rows.length} endpoint operations`);
