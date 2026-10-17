/**
 * OAuth client helpers: discovery, PKCE, request building, error mapping,
 * agent names, scopes, sign-in mode detection and the browser opener.
 */

import { EventEmitter } from "node:events";
import { afterEach, describe, expect, it, vi } from "vitest";
import { detectSignInMode, openBrowser } from "../src/browser.js";
import {
  AGENT_NAME_MAX_CHARS,
  OAuthError,
  agentName,
  authorizationUrl,
  discover,
  grants,
  missingScopeMessage,
  normalizeServerUrl,
  pkceChallenge,
  pkcePair,
  pollDeviceCode,
  randomState,
  requestDeviceAuthorization,
  sameServer,
  sanitizeAgentName,
  type ServerMetadata,
} from "../src/oauth.js";

function metadataFor(issuer: string) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    device_authorization_endpoint: `${issuer}/oauth/device_authorization`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["clipboard:read", "clipboard:write", "clipboard:delete", "devices:manage"],
    authorization_response_iss_parameter_supported: true,
  };
}

function serve(routes: Record<string, { status?: number; body: unknown; type?: string; headers?: Record<string, string> }>) {
  const calls: { url: string; init?: RequestInit }[] = [];
  globalThis.fetch = vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    calls.push({ url, init });
    const route = routes[url];
    if (!route) return new Response("<!doctype html><title>cpmesh</title>", { status: 200, headers: { "Content-Type": "text/html" } });
    const text = typeof route.body === "string" ? route.body : JSON.stringify(route.body);
    return new Response(text, {
      status: route.status ?? 200,
      headers: { "Content-Type": route.type ?? "application/json", ...route.headers },
    });
  }) as typeof fetch;
  return calls;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("server URLs and discovery", () => {
  it("normalizes server URLs and refuses other schemes, credentials and queries", () => {
    expect(normalizeServerUrl(" HTTPS://CPMesh.com:443/ ")).toBe("https://cpmesh.com");
    expect(normalizeServerUrl("http://127.0.0.1:39271")).toBe("http://127.0.0.1:39271");
    expect(normalizeServerUrl("https://host.example/cpmesh//")).toBe("https://host.example/cpmesh");
    expect(() => normalizeServerUrl("cpmesh.com")).toThrow(/https:\/\//);
    expect(() => normalizeServerUrl("ftp://cpmesh.com")).toThrow(/https:\/\//);
    expect(() => normalizeServerUrl("https://user:pw@cpmesh.com")).toThrow(/credentials/);
    expect(() => normalizeServerUrl("https://cpmesh.com/?x=1")).toThrow(/query/);
    expect(sameServer("https://cpmesh.com/", "https://CPMESH.com")).toBe(true);
    expect(sameServer("https://cpmesh.com", "https://other.example")).toBe(false);
  });

  it("discovers the endpoints from the server's metadata without credentials", async () => {
    const calls = serve({ "https://cpmesh.com/.well-known/oauth-authorization-server": { body: metadataFor("https://cpmesh.com") } });
    const metadata = await discover("https://cpmesh.com/");
    expect(metadata).toMatchObject({
      issuer: "https://cpmesh.com",
      server_url: "https://cpmesh.com",
      token_endpoint: "https://cpmesh.com/oauth/token",
      device_authorization_endpoint: "https://cpmesh.com/oauth/device_authorization",
      revocation_endpoint: "https://cpmesh.com/oauth/revoke",
    });
    expect((calls[0]!.init!.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it("refuses metadata whose issuer is not the server URL", async () => {
    serve({ "https://cpmesh.com/.well-known/oauth-authorization-server": { body: metadataFor("https://evil.example") } });
    await expect(discover("https://cpmesh.com")).rejects.toThrow(/identifies itself as https:\/\/evil\.example/);
  });

  it("asks to upgrade a server that answers with its web page (HTML)", async () => {
    serve({});
    await expect(discover("https://old.example")).rejects.toThrow(/does not support signing in AI agents.*upgrade/s);
  });

  it("names BASE_URL when the server cannot sign agents in", async () => {
    serve({
      "https://cpmesh.local/.well-known/oauth-authorization-server": {
        status: 500, body: { error: "server_error", error_description: "agents cannot sign in: this server has no BASE_URL configured" },
      },
    });
    await expect(discover("https://cpmesh.local")).rejects.toThrow(/no BASE_URL configured.*must set BASE_URL/);
  });

  it("refuses endpoints outside the issuer, and servers without S256 or iss", async () => {
    const issuer = "https://cpmesh.com";
    const url = `${issuer}/.well-known/oauth-authorization-server`;
    serve({ [url]: { body: { ...metadataFor(issuer), token_endpoint: "https://elsewhere.example/oauth/token" } } });
    await expect(discover(issuer)).rejects.toThrow(/token_endpoint .* is not under/);
    serve({ [url]: { body: { ...metadataFor(issuer), code_challenge_methods_supported: ["plain"] } } });
    await expect(discover(issuer)).rejects.toThrow(/S256/);
    serve({ [url]: { body: { ...metadataFor(issuer), authorization_response_iss_parameter_supported: false } } });
    await expect(discover(issuer)).rejects.toThrow(/RFC 9207/);
  });

  it("tries the RFC 8414 location first for a server under a path prefix, then the server's own path", async () => {
    const calls = serve({
      "https://host.example/cpmesh/.well-known/oauth-authorization-server": { body: metadataFor("https://host.example/cpmesh") },
    });
    const metadata = await discover("https://host.example/cpmesh");
    expect(metadata.token_endpoint).toBe("https://host.example/cpmesh/oauth/token");
    expect(calls.map((c) => c.url)).toEqual([
      "https://host.example/.well-known/oauth-authorization-server/cpmesh",
      "https://host.example/cpmesh/.well-known/oauth-authorization-server",
    ]);
  });
});

describe("authorization requests", () => {
  it("makes S256 PKCE pairs (RFC 7636 appendix B) and unguessable states", () => {
    expect(pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    const { verifier, challenge } = pkcePair();
    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(challenge).toBe(pkceChallenge(verifier));
    expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(pkcePair().verifier).not.toBe(verifier);
    expect(randomState()).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("asks for every scope by leaving scope out, with S256, the loopback redirect and the agent name", () => {
    const metadata = { ...metadataFor("https://cpmesh.com"), server_url: "https://cpmesh.com" } as ServerMetadata;
    const url = new URL(authorizationUrl(metadata, {
      redirectUri: "http://127.0.0.1:53682/callback", state: "st", challenge: "ch", agentName: "Claude Code via cpmesh-mcp on laptop",
    }));
    expect(url.origin + url.pathname).toBe("https://cpmesh.com/oauth/authorize");
    expect(Object.fromEntries(url.searchParams)).toEqual({
      client_id: "cpmesh-mcp", redirect_uri: "http://127.0.0.1:53682/callback", response_type: "code", state: "st",
      code_challenge: "ch", code_challenge_method: "S256", agent_name: "Claude Code via cpmesh-mcp on laptop",
    });
  });

  it("maps token endpoint errors, keeping slow_down's interval and Retry-After", async () => {
    serve({
      "https://cpmesh.com/oauth/token": {
        status: 400, body: { error: "slow_down", error_description: "polling too often; wait 10 seconds between requests", interval: 10 },
      },
    });
    const error = await pollDeviceCode("https://cpmesh.com/oauth/token", "dc").catch((e: unknown) => e);
    expect(error).toBeInstanceOf(OAuthError);
    expect(error).toMatchObject({ status: 400, error: "slow_down", extra: { interval: 10 } });
    serve({
      "https://cpmesh.com/oauth/token": {
        status: 503, body: { error: "temporarily_unavailable", error_description: "retry" }, headers: { "Retry-After": "5" },
      },
    });
    const unavailable = await pollDeviceCode("https://cpmesh.com/oauth/token", "dc").catch((e: unknown) => e) as OAuthError;
    expect(unavailable.transient).toBe(true);
    expect(unavailable.extra.retryAfter).toBe(5);
  });

  it("refuses device verification links outside the server", async () => {
    const metadata = { ...metadataFor("https://cpmesh.com"), server_url: "https://cpmesh.com" } as ServerMetadata;
    const answer = {
      device_code: "dc", user_code: "BCDF-GHJK", verification_uri: "https://cpmesh.com/activate",
      verification_uri_complete: "https://cpmesh.com/activate?user_code=BCDF-GHJK", expires_in: 600, interval: 5,
    };
    const calls = serve({ "https://cpmesh.com/oauth/device_authorization": { body: answer } });
    await expect(requestDeviceAuthorization(metadata, "Agent via cpmesh-mcp on host")).resolves.toMatchObject({ user_code: "BCDF-GHJK" });
    expect(Object.fromEntries(new URLSearchParams(String(calls[0]!.init!.body)))).toEqual({
      client_id: "cpmesh-mcp", agent_name: "Agent via cpmesh-mcp on host",
    });
    serve({ "https://cpmesh.com/oauth/device_authorization": { body: { ...answer, verification_uri_complete: "https://phish.example/activate?user_code=X" } } });
    await expect(requestDeviceAuthorization(metadata, "")).rejects.toThrow(/outside its own URL/);
  });
});

describe("agent name", () => {
  it("names the client, cpmesh-mcp and the host", () => {
    expect(agentName("Claude Code", "laptop")).toBe("Claude Code via cpmesh-mcp on laptop");
    expect(agentName(undefined, "build-box")).toBe("AI agent via cpmesh-mcp on build-box");
    expect(agentName("\u0007\u202e", "box")).toBe("AI agent via cpmesh-mcp on box");
  });

  it("removes control and bidirectional formatting characters the server refuses", () => {
    const name = sanitizeAgentName(" Evil\u202eAgent\u2066 \u0000via\u200f\tcpmesh\nmcp\u2028on\u061chost\u007f ");
    expect(name).toBe("EvilAgent via cpmesh mcp onhost");
    expect(name).not.toMatch(/[\p{Cc}\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u);
    expect(sanitizeAgentName("a\ud800b")).toBe("ab");
  });

  it("keeps at most 100 characters, counting code points", () => {
    const long = sanitizeAgentName(`${"😀".repeat(150)} via cpmesh-mcp on host`);
    expect(Array.from(long)).toHaveLength(AGENT_NAME_MAX_CHARS);
    expect(long).toBe("😀".repeat(100));
    expect(Array.from(agentName("x".repeat(120), "host")).length).toBeLessThanOrEqual(AGENT_NAME_MAX_CHARS);
    expect(sanitizeAgentName(`${"a".repeat(99)} b`)).toBe("a".repeat(99));
  });
});

describe("scopes", () => {
  it("checks granted scopes, leaving unknown grants to the server", () => {
    expect(grants("clipboard:read clipboard:write", "clipboard:read")).toBe(true);
    expect(grants("clipboard:write", "clipboard:read")).toBe(false);
    expect(grants("", "clipboard:write")).toBe(false);
    expect(grants(undefined, "devices:manage")).toBe(true);
  });

  it("tells the agent how to get the missing scope", () => {
    expect(missingScopeMessage("clipboard:read")).toMatch(/can only send.*re-authorize the agent with read access: call cpmesh_login/);
    expect(missingScopeMessage("clipboard:write")).toMatch(/can't share text.*send access/);
    expect(missingScopeMessage("clipboard:read clipboard:write")).toMatch(/clipboard:write/);
    expect(missingScopeMessage("clipboard:delete")).toMatch(/can't delete clipboard entries.*off by default.*clipboard:delete/);
    expect(missingScopeMessage("devices:manage")).toMatch(/can't remove devices.*devices:manage/);
    expect(missingScopeMessage(undefined)).toMatch(/cannot use this cpmesh feature/);
  });
});

describe("sign-in mode", () => {
  const none = () => false;

  it("uses the browser on a desktop and the device flow over SSH, in containers or without a display", () => {
    expect(detectSignInMode({ DISPLAY: ":0" }, "linux", none)).toEqual({ mode: "browser" });
    expect(detectSignInMode({ WAYLAND_DISPLAY: "wayland-0" }, "linux", none)).toEqual({ mode: "browser" });
    expect(detectSignInMode({}, "darwin", none)).toEqual({ mode: "browser" });
    expect(detectSignInMode({}, "win32", none)).toEqual({ mode: "browser" });
    expect(detectSignInMode({}, "linux", none)).toMatchObject({ mode: "device", reason: expect.stringMatching(/display/) });
    for (const env of [{ SSH_CONNECTION: "10.0.0.2 51000 10.0.0.1 22" }, { SSH_TTY: "/dev/pts/1" }]) {
      expect(detectSignInMode({ DISPLAY: ":0", ...env }, "linux", none)).toMatchObject({ mode: "device", reason: expect.stringMatching(/SSH/) });
      expect(detectSignInMode(env, "darwin", none).mode).toBe("device");
    }
    for (const env of [{ container: "podman" }, { CODESPACES: "true" }, { REMOTE_CONTAINERS: "true" }]) {
      expect(detectSignInMode({ DISPLAY: ":0", ...env }, "linux", none)).toMatchObject({ mode: "device", reason: expect.stringMatching(/container/) });
    }
    for (const marker of ["/.dockerenv", "/run/.containerenv"]) {
      expect(detectSignInMode({ DISPLAY: ":0" }, "linux", (path) => path === marker).mode).toBe("device");
    }
  });

  function fakeSpawn(behave: (child: EventEmitter) => void) {
    const spawned: { command: string; args: string[]; options: Record<string, unknown> }[] = [];
    const spawn = ((command: string, args: string[], options: Record<string, unknown>) => {
      spawned.push({ command, args, options });
      const child = Object.assign(new EventEmitter(), { unref: () => undefined });
      setImmediate(() => behave(child));
      return child;
    }) as unknown as typeof import("node:child_process").spawn;
    return { spawn, spawned };
  }

  it("opens the browser without a shell or output and reports whether it could", async () => {
    const url = "https://cpmesh.com/oauth/authorize?a=1&b=2";
    const ok = fakeSpawn((child) => child.emit("exit", 0));
    await expect(openBrowser(url, "linux", ok.spawn)).resolves.toBe(true);
    expect(ok.spawned[0]).toMatchObject({ command: "xdg-open", args: [url], options: { stdio: "ignore", detached: true } });
    await expect(openBrowser(url, "darwin", fakeSpawn((child) => child.emit("exit", 0)).spawn)).resolves.toBe(true);
    const windows = fakeSpawn((child) => child.emit("spawn"));
    await expect(openBrowser(url, "win32", windows.spawn)).resolves.toBe(true);
    expect(windows.spawned[0]).toMatchObject({ command: "rundll32.exe", args: ["url.dll,FileProtocolHandler", url] });
    await expect(openBrowser(url, "linux", fakeSpawn((child) => child.emit("error", new Error("ENOENT"))).spawn)).resolves.toBe(false);
    await expect(openBrowser(url, "linux", fakeSpawn((child) => child.emit("exit", 3)).spawn)).resolves.toBe(false);
  });
});
