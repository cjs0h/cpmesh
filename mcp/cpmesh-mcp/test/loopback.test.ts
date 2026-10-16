/**
 * The loopback listener of the browser sign-in: one callback with our state,
 * from our issuer, then it closes.
 */

import { request } from "node:http";
import { describe, expect, it } from "vitest";
import { AuthorizationError, startLoopback } from "../src/loopback.js";

const ISSUER = "https://cpmesh.com";

/** GET on the listener; `host` overrides the Host header. */
function get(url: string, host?: string): Promise<{ status: number; headers: Record<string, unknown>; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(url, { method: "GET", headers: host ? { Host: host } : {} }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk: string) => (body += chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on("error", reject);
    req.end();
  });
}

function callback(redirectUri: string, params: Record<string, string>): string {
  return `${redirectUri}?${new URLSearchParams(params)}`;
}

describe("loopback redirect", () => {
  it("listens on 127.0.0.1 and accepts the callback with our state and issuer, once", async () => {
    const loopback = await startLoopback({ state: "s1", issuer: ISSUER, timeoutMs: 60_000 });
    expect(loopback.redirectUri).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/callback$/);

    const page = await get(callback(loopback.redirectUri, { code: "the-code", state: "s1", iss: ISSUER }));
    expect(page.status).toBe(200);
    expect(page.body).toMatch(/You can close this tab/);
    expect(page.headers).toMatchObject({
      "cache-control": "no-store", "referrer-policy": "no-referrer", "x-frame-options": "DENY",
    });
    await expect(loopback.code).resolves.toBe("the-code");
    // A second callback finds the listener closed
    await expect(get(callback(loopback.redirectUri, { code: "other", state: "s1", iss: ISSUER }))).rejects.toThrow();
  });

  it("ignores requests without our state, for another host or path, and keeps waiting", async () => {
    const loopback = await startLoopback({ state: "s2", issuer: ISSUER, timeoutMs: 60_000 });
    const { port } = new URL(loopback.redirectUri);

    expect((await get(callback(loopback.redirectUri, { code: "forged", state: "guess", iss: ISSUER }))).status).toBe(400);
    expect((await get(callback(loopback.redirectUri, { code: "forged", iss: ISSUER }))).status).toBe(400);
    expect((await get(`${loopback.redirectUri}?code=c&state=s2&state=s2&iss=${encodeURIComponent(ISSUER)}`)).status).toBe(400);
    expect((await get(callback(loopback.redirectUri, { code: "rebound", state: "s2", iss: ISSUER }), `attacker.example:${port}`)).status).toBe(400);
    expect((await get(`http://127.0.0.1:${port}/favicon.ico`)).status).toBe(404);

    expect((await get(callback(loopback.redirectUri, { code: "real", state: "s2", iss: ISSUER }))).status).toBe(200);
    await expect(loopback.code).resolves.toBe("real");
  });

  it("refuses an answer from another issuer (RFC 9207) and ends the sign-in", async () => {
    const loopback = await startLoopback({ state: "s3", issuer: ISSUER, timeoutMs: 60_000 });
    const page = await get(callback(loopback.redirectUri, { code: "mixed-up", state: "s3", iss: "https://evil.example" }));
    expect(page.status).toBe(400);
    expect(page.body).toMatch(/Sign-in failed/);
    await expect(loopback.code).rejects.toMatchObject({ error: "issuer_mismatch" });
    const missing = await startLoopback({ state: "s4", issuer: ISSUER, timeoutMs: 60_000 });
    await get(callback(missing.redirectUri, { code: "no-iss", state: "s4" }));
    await expect(missing.code).rejects.toMatchObject({ error: "issuer_mismatch" });
  });

  it("reports an error callback, such as the user denying the request", async () => {
    const loopback = await startLoopback({ state: "s5", issuer: ISSUER, timeoutMs: 60_000 });
    const page = await get(callback(loopback.redirectUri, {
      error: "access_denied", error_description: "the user denied the request", state: "s5", iss: ISSUER,
    }));
    expect(page.body).toMatch(/Sign-in cancelled/);
    const error = await loopback.code.catch((e: unknown) => e);
    expect(error).toBeInstanceOf(AuthorizationError);
    expect(error).toMatchObject({ error: "access_denied", message: expect.stringMatching(/cancelled the sign-in/) });

    const refused = await startLoopback({ state: "s6", issuer: ISSUER, timeoutMs: 60_000 });
    await get(callback(refused.redirectUri, { error: "invalid_scope", error_description: "unknown scope", state: "s6", iss: ISSUER }));
    await expect(refused.code).rejects.toMatchObject({ error: "invalid_scope", message: expect.stringMatching(/invalid_scope: unknown scope/) });
  });

  it("times out and closes the listener", async () => {
    const loopback = await startLoopback({ state: "s7", issuer: ISSUER, timeoutMs: 50 });
    await expect(loopback.code).rejects.toMatchObject({ error: "timeout" });
    await expect(get(callback(loopback.redirectUri, { code: "late", state: "s7", iss: ISSUER }))).rejects.toThrow();
  });

  it("stops waiting when closed", async () => {
    const loopback = await startLoopback({ state: "s8", issuer: ISSUER, timeoutMs: 60_000 });
    loopback.close();
    await expect(loopback.code).rejects.toMatchObject({ error: "cancelled" });
  });
});
