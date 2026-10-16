/**
 * OAuth client for signing this MCP server in to a cpmesh server: discovery
 * (RFC 8414), PKCE (RFC 7636), the token endpoint (RFC 6749), the device
 * authorization grant (RFC 8628) and revocation (RFC 7009).
 *
 * The client is the public client `cpmesh-mcp` (no secret). The user signs in
 * and approves on the cpmesh website, so passwords and second factors never
 * pass through the agent. Requests to /oauth/* never carry a bearer token.
 */

import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";

export const CLIENT_ID = "cpmesh-mcp";
export const DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
export const SCOPES = ["clipboard:read", "clipboard:write", "clipboard:delete", "devices:manage"] as const;
export type Scope = (typeof SCOPES)[number];

/** The server rejects longer agent names (contract §2.1). */
export const AGENT_NAME_MAX_CHARS = 100;
const REQUEST_TIMEOUT_MS = 30_000;

let userAgent = "cpmesh-mcp";

/** Sent with every OAuth request; the device consent page shows it. */
export function setUserAgent(value: string): void {
  userAgent = value;
}

/**
 * An OAuth error answer (RFC 6749 §5.2), or `status` 0 when the server could
 * not be reached. `unsent` marks network failures that happened before the
 * request reached the server, so whatever it carried was not used.
 */
export class OAuthError extends Error {
  constructor(
    readonly status: number,
    readonly error: string,
    readonly description: string,
    readonly extra: { interval?: number; retryAfter?: number; unsent?: boolean } = {},
  ) {
    super(description);
  }

  /** Worth retrying later: the server asked to (429, 503) or a proxy could not reach it. */
  get transient(): boolean {
    return this.status === 429 || this.status === 503 || (this.status === 0 && this.extra.unsent === true);
  }
}

// === Server URL and discovery ===

/** `https://host[:port][/path]`: lower-case scheme and host, no default port, no trailing slash. */
export function normalizeServerUrl(input: string): string {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new Error(`Invalid server URL "${input}": it must start with https:// (or http:// for a local server).`);
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Server URL must start with https:// (or http:// for a local server).");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("Server URL must not contain credentials, a query or a fragment.");
  }
  return `${url.protocol}//${url.host}${url.pathname.replace(/\/+$/, "")}`;
}

/** Whether two server URLs name the same server (spelling differences aside). */
export function sameServer(a: string, b: string): boolean {
  const normalize = (url: string) => {
    try {
      return normalizeServerUrl(url);
    } catch {
      return url.trim().replace(/\/+$/, "").toLowerCase();
    }
  };
  return normalize(a) === normalize(b);
}

export interface ServerMetadata {
  /** The issuer exactly as the server reports it (compared with `iss`, RFC 9207). */
  issuer: string;
  /** The server URL, normalized; equal to the normalized issuer. */
  server_url: string;
  authorization_endpoint: string;
  token_endpoint: string;
  device_authorization_endpoint: string;
  revocation_endpoint: string;
}

const metadataSchema = z.object({
  issuer: z.string(),
  authorization_endpoint: z.string(),
  token_endpoint: z.string(),
  device_authorization_endpoint: z.string(),
  revocation_endpoint: z.string(),
  code_challenge_methods_supported: z.array(z.string()).optional(),
  authorization_response_iss_parameter_supported: z.boolean().optional(),
});

/**
 * Fetches and checks the server's metadata. The issuer must be the server URL
 * (so a sign-in can't be mixed up with another server's), and every endpoint
 * must live under it. Self-hosts under a path prefix are tried at the RFC 8414
 * location first, then at `{server_url}/.well-known/oauth-authorization-server`.
 */
export async function discover(serverUrl: string): Promise<ServerMetadata> {
  const expected = normalizeServerUrl(serverUrl);
  const { origin, pathname } = new URL(expected);
  const locations = [`${expected}/.well-known/oauth-authorization-server`];
  if (pathname && pathname !== "/") {
    locations.unshift(`${origin}/.well-known/oauth-authorization-server${pathname}`);
  }
  let failure: unknown;
  for (const location of locations) {
    try {
      return await fetchMetadata(location, expected);
    } catch (error) {
      failure = error;
    }
  }
  throw failure;
}

function upgradeRequired(server: string): Error {
  return new Error(
    `The cpmesh server at ${server} does not support signing in AI agents through the browser yet ` +
      "(it has no OAuth metadata at /.well-known/oauth-authorization-server). This version of cpmesh-mcp " +
      "needs a server with OAuth for agents: ask the server's administrator to upgrade it.",
  );
}

async function fetchMetadata(location: string, expected: string): Promise<ServerMetadata> {
  let res: Response;
  try {
    res = await fetch(location, {
      headers: { Accept: "application/json", "User-Agent": userAgent },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    throw new Error(`Could not reach the cpmesh server at ${expected}: ${describeNetworkError(error)}`);
  }
  const body = parseJsonObject(await res.text().catch(() => ""));
  if (!res.ok) {
    if (res.status === 404 || res.status === 405) throw upgradeRequired(expected);
    if (typeof body?.error === "string") {
      const description = typeof body.error_description === "string" ? body.error_description : body.error;
      throw new Error(
        `The cpmesh server at ${expected} cannot sign in AI agents (${description}).` +
          (body.error === "server_error" ? " Its administrator must set BASE_URL to the server's public URL." : ""),
      );
    }
    throw new Error(`OAuth discovery at ${location} failed: HTTP ${res.status}`);
  }
  // An older server answers with its web dashboard (HTML)
  if (!body) throw upgradeRequired(expected);

  const parsed = metadataSchema.safeParse(body);
  if (!parsed.success) throw new Error(`The cpmesh server at ${expected} sent invalid OAuth metadata.`);
  const metadata = parsed.data;
  let issuer: string;
  try {
    issuer = normalizeServerUrl(metadata.issuer);
  } catch {
    throw new Error(`The cpmesh server at ${expected} sent an invalid issuer (${metadata.issuer}).`);
  }
  if (issuer !== expected) {
    throw new Error(
      `The server at ${expected} identifies itself as ${metadata.issuer} (its BASE_URL), so the sign-in was not started. ` +
        `Use ${metadata.issuer} as server_url (or in CPMESH_SERVER_URL), or ask the administrator to correct BASE_URL.`,
    );
  }
  if (metadata.code_challenge_methods_supported && !metadata.code_challenge_methods_supported.includes("S256")) {
    throw new Error(`The cpmesh server at ${expected} does not support PKCE with S256; upgrade the server.`);
  }
  if (metadata.authorization_response_iss_parameter_supported !== true) {
    throw new Error(`The cpmesh server at ${expected} does not identify itself in sign-in answers (RFC 9207); upgrade the server.`);
  }
  const endpoints = {
    authorization_endpoint: metadata.authorization_endpoint,
    token_endpoint: metadata.token_endpoint,
    device_authorization_endpoint: metadata.device_authorization_endpoint,
    revocation_endpoint: metadata.revocation_endpoint,
  };
  for (const [name, value] of Object.entries(endpoints)) {
    if (!within(value, issuer)) {
      throw new Error(`The cpmesh server's ${name} (${value}) is not under its own URL ${issuer}; refusing to use it.`);
    }
  }
  return { issuer: metadata.issuer, server_url: issuer, ...endpoints };
}

/** Whether `url` is an http(s) URL under the (normalized) `base`, without credentials, query or fragment. */
export function within(url: string, base: string): boolean {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return false;
    if (parsed.username || parsed.password || parsed.search || parsed.hash) return false;
    return `${parsed.protocol}//${parsed.host}${parsed.pathname}`.startsWith(`${base}/`);
  } catch {
    return false;
  }
}

// === Authorization code with PKCE ===

/** A PKCE pair: a 43-character base64url verifier and its S256 challenge. */
export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: pkceChallenge(verifier) };
}

export function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

/** An unguessable `state` for one authorization request. */
export function randomState(): string {
  return randomBytes(32).toString("base64url");
}

/**
 * The page that asks the user to approve this agent. No `scope`: the agent asks
 * for every scope and the user chooses on the consent page.
 */
export function authorizationUrl(
  metadata: ServerMetadata,
  request: { redirectUri: string; state: string; challenge: string; agentName: string },
): string {
  const url = new URL(metadata.authorization_endpoint);
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("redirect_uri", request.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", request.state);
  url.searchParams.set("code_challenge", request.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (request.agentName) url.searchParams.set("agent_name", request.agentName);
  return url.toString();
}

// === Token endpoint ===

const tokenSchema = z.object({
  access_token: z.string().min(1),
  token_type: z.string().refine((type) => type.toLowerCase() === "bearer"),
  expires_in: z.number().optional(),
  refresh_token: z.string().min(1),
  /** What the grant allows; may be less than requested (send-only agents). */
  scope: z.string().optional(),
  user_id: z.string().uuid(),
  grant_id: z.string().uuid(),
});
/** Tokens for this agent, the scopes the user granted, and the account and grant they belong to. */
export type TokenSet = z.infer<typeof tokenSchema>;

export async function requestTokens(tokenEndpoint: string, params: Record<string, string>): Promise<TokenSet> {
  const body = await postForm(tokenEndpoint, params);
  const parsed = tokenSchema.safeParse(body);
  if (!parsed.success) throw new OAuthError(200, "invalid_response", "the cpmesh server sent an invalid token response");
  return parsed.data;
}

export function exchangeCode(
  tokenEndpoint: string,
  code: string,
  redirectUri: string,
  verifier: string,
): Promise<TokenSet> {
  return requestTokens(tokenEndpoint, {
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
  });
}

export function refreshTokens(tokenEndpoint: string, refreshToken: string): Promise<TokenSet> {
  return requestTokens(tokenEndpoint, { grant_type: "refresh_token", refresh_token: refreshToken });
}

export function pollDeviceCode(tokenEndpoint: string, deviceCode: string): Promise<TokenSet> {
  return requestTokens(tokenEndpoint, { grant_type: DEVICE_CODE_GRANT_TYPE, device_code: deviceCode });
}

// === Device authorization (RFC 8628) ===

const deviceAuthorizationSchema = z.object({
  device_code: z.string().min(1).max(1024),
  user_code: z.string().min(1).max(64),
  verification_uri: z.string(),
  verification_uri_complete: z.string().optional(),
  expires_in: z.number().int().positive(),
  interval: z.number().int().positive().optional(),
});
export type DeviceAuthorization = z.infer<typeof deviceAuthorizationSchema>;

export async function requestDeviceAuthorization(
  metadata: ServerMetadata,
  agentName: string,
): Promise<DeviceAuthorization> {
  const body = await postForm(metadata.device_authorization_endpoint, agentName ? { agent_name: agentName } : {});
  const parsed = deviceAuthorizationSchema.safeParse(body);
  if (!parsed.success) throw new Error("The cpmesh server sent an invalid device authorization response.");
  const answer = parsed.data;
  // The user follows these links, so they must point at the server itself
  if (!within(answer.verification_uri, metadata.server_url) ||
      (answer.verification_uri_complete !== undefined && !within(answer.verification_uri_complete.split("?")[0]!, metadata.server_url))) {
    throw new Error("The cpmesh server sent a verification link outside its own URL; refusing to show it.");
  }
  return answer;
}

// === Revocation (RFC 7009) ===

/** Revokes this agent's grant (the server also removes its device). */
export async function revokeToken(revocationEndpoint: string, token: string): Promise<void> {
  await postForm(revocationEndpoint, { token, token_type_hint: "refresh_token" });
}

// === Transport ===

async function postForm(endpoint: string, params: Record<string, string>): Promise<unknown> {
  let res: Response;
  try {
    res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        "User-Agent": userAgent,
      },
      body: new URLSearchParams({ client_id: CLIENT_ID, ...params }).toString(),
      // Tokens and codes must not follow a redirect to another address
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    throw new OAuthError(0, "network_error", `could not reach the cpmesh server: ${describeNetworkError(error)}`, {
      unsent: wasNotSent(error),
    });
  }
  const text = await res.text().catch(() => "");
  const body = parseJsonObject(text);
  if (res.ok) return body ?? {};
  const error = typeof body?.error === "string" ? body.error : `http_${res.status}`;
  const description =
    typeof body?.error_description === "string" ? body.error_description : `HTTP ${res.status}${res.statusText ? ` ${res.statusText}` : ""}`;
  throw new OAuthError(res.status, error, description, {
    interval: typeof body?.interval === "number" && Number.isInteger(body.interval) && body.interval > 0 ? body.interval : undefined,
    retryAfter: retryAfterSeconds(res.headers.get("retry-after")),
  });
}

function parseJsonObject(text: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(text);
    return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function retryAfterSeconds(value: string | null): number | undefined {
  if (!value) return undefined;
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : undefined;
}

const UNSENT_CODES = new Set([
  "ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "ENETUNREACH", "EHOSTUNREACH", "UND_ERR_CONNECT_TIMEOUT",
]);

function errorCode(error: unknown): string | undefined {
  const cause = (error as { cause?: { code?: unknown } } | null)?.cause;
  return typeof cause?.code === "string" ? cause.code : undefined;
}

/** Failures before the request was sent: connecting, resolving the name, or the TLS handshake. */
function wasNotSent(error: unknown): boolean {
  const code = errorCode(error);
  return code !== undefined && (UNSENT_CODES.has(code) || /CERT|TLS|SELF_SIGNED|UNABLE_TO_VERIFY/.test(code));
}

export function describeNetworkError(error: unknown): string {
  const name = (error as { name?: unknown } | null)?.name;
  if (name === "TimeoutError" || name === "AbortError") return "the request timed out";
  return errorCode(error) ?? (error instanceof Error ? error.message : String(error));
}

// === Agent name ===

/** Characters the server refuses because they reorder or break the text around them. */
const FORMATTING = new Set([0x061c, 0x200e, 0x200f, 0x2028, 0x2029, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069]);

/**
 * How the agent introduces itself on the consent page:
 * "<client name> via cpmesh-mcp on <hostname>", at most 100 characters,
 * without control or bidirectional formatting characters.
 */
export function agentName(clientName: string | undefined, host: string): string {
  const client = clientName && sanitizeAgentName(clientName) ? clientName : "AI agent";
  return sanitizeAgentName(`${client} via cpmesh-mcp on ${host}`);
}

export function sanitizeAgentName(raw: string): string {
  let cleaned = "";
  for (const character of raw) {
    const point = character.codePointAt(0)!;
    if (point >= 0xd800 && point <= 0xdfff) continue; // a lone surrogate
    if (/\s/u.test(character)) cleaned += " ";
    else if (!/\p{Cc}/u.test(character) && !FORMATTING.has(point)) cleaned += character;
  }
  const characters = Array.from(cleaned.replace(/ {2,}/g, " ").trim());
  return characters.slice(0, AGENT_NAME_MAX_CHARS).join("").trim();
}

// === Scopes ===

export function scopesOf(scope: string | undefined): string[] {
  return (scope ?? "").split(/\s+/).filter(Boolean);
}

/** Whether a granted scope string allows `needed`. Unknown grants (no scope stored) are left to the server. */
export function grants(scope: string | undefined, needed: Scope): boolean {
  return scope === undefined || scopesOf(scope).includes(needed);
}

const SCOPE_HELP: Record<Scope, { cannot: string; why: string; turnOn: string }> = {
  "clipboard:read": {
    cannot: "read the clipboard",
    why: "the user authorized it without clipboard:read, so it can only send",
    turnOn: "reading the clipboard (clipboard:read)",
  },
  "clipboard:write": {
    cannot: "share text to the user's devices",
    why: "the user authorized it without clipboard:write",
    turnOn: "sending to the clipboard (clipboard:write)",
  },
  "clipboard:delete": {
    cannot: "delete clipboard entries",
    why: "the user did not grant clipboard:delete (it is off by default)",
    turnOn: "deleting clipboard entries (clipboard:delete)",
  },
  "devices:manage": {
    cannot: "remove devices",
    why: "the user did not grant devices:manage (it is off by default)",
    turnOn: "managing devices (devices:manage)",
  },
};

/** What to tell the agent when its grant lacks `scope` (as the server names it in `insufficient_scope`). */
export function missingScopeMessage(scope: string | undefined): string {
  const needed = scopesOf(scope);
  // The WebSocket asks for read or write; the MCP server only opens it to send
  const known = (needed.includes("clipboard:write") ? "clipboard:write" : needed.find((s): s is Scope => s in SCOPE_HELP));
  if (!known) return "Agents cannot use this cpmesh feature (insufficient_scope).";
  const help = SCOPE_HELP[known];
  const access = known === "clipboard:read" ? " with read access" : known === "clipboard:write" ? " with send access" : "";
  return (
    `This agent can't ${help.cannot}: ${help.why}. To allow it, ask the user to re-authorize the agent${access}: ` +
    `call cpmesh_login, then turn on ${help.turnOn} on the cpmesh approval page.`
  );
}
