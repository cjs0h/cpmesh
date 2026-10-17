#!/usr/bin/env node
/**
 * End-to-end smoke test: drives the built MCP server (dist/index.js) over
 * stdio exactly like a real MCP client would, against a live cpmesh server.
 *
 * The script also plays the user: it signs in to the cpmesh web API with the
 * account's password (and two-factor code), then approves the agent's sign-in
 * request (device authorization) the way the dashboard's approval page does.
 * The agent then registers as a device, pushes a clipboard entry, retries it,
 * restarts, reads it back decrypted, searches history and lists devices. It
 * re-authorizes the agent as send-only through the browser flow, with the
 * script as the browser (same device, no new pairing; reading is refused),
 * and finally signs out, which revokes the agent and removes its device from
 * the account. No real browser is opened.
 *
 * NOTE: this creates a real device registration under the account. For a
 * fresh account the MCP device is the first device and is auto-approved. For
 * an account with existing approved devices the registration stays pending —
 * the script then exits and tells you to finish pairing interactively.
 *
 * Accounts with two-factor authentication also need the current 6-digit code
 * from the authenticator app (or a recovery code) as the fourth argument.
 *
 * Usage (run after `npm run build`):
 *   CPMESH_HOME=$(mktemp -d) node scripts/e2e-smoke.mjs <server-url> <username> <password> [code]
 */

import { spawn } from "node:child_process";
import { once } from "node:events";
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join, dirname, delimiter } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const [
  serverArgument = process.env.CPMESH_E2E_URL,
  username = process.env.CPMESH_E2E_USERNAME,
  password = process.env.CPMESH_E2E_PASSWORD,
  code = process.env.CPMESH_E2E_CODE,
] = process.argv.slice(2);
if (!serverArgument || !username || !password) {
  console.error("Usage: node scripts/e2e-smoke.mjs <server-url> <username> <password> [code]");
  process.exit(1);
}
const serverUrl = serverArgument.replace(/\/+$/, "");

// === The user's side: the cpmesh web API, as the dashboard uses it ===

async function web(path, { method = "GET", body, token } = {}) {
  const response = await fetch(serverUrl + path, {
    method,
    headers: { ...(body && { "Content-Type": "application/json" }), ...(token && { Authorization: "Bearer " + token }) },
    body: body && JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  const text = await response.text();
  let json;
  try { json = text ? JSON.parse(text) : undefined; } catch { json = text; }
  return { status: response.status, body: json };
}

/** Signs the user in with the password and, when asked, the two-factor code. */
async function webSignIn() {
  const login = await web("/api/auth/login", { method: "POST", body: { username, password } });
  if (login.status === 200 && login.body?.access_token) return login.body.access_token;
  if (login.status !== 403 || login.body?.code !== "mfa_required") {
    throw new Error(`Web sign-in failed: HTTP ${login.status} ${JSON.stringify(login.body)}`);
  }
  if (login.body.stage === "enroll") {
    throw new Error("Set up two-factor authentication on the web dashboard first, then pass its current code.");
  }
  if (!code) throw new Error("The account uses two-factor authentication: pass the current code (or a recovery code) as the fourth argument.");
  const compact = code.replace(/\s+/g, "");
  const verify = await web("/api/mfa/verify", {
    method: "POST", token: login.body.mfa_token,
    body: /^\d{6}$/.test(compact) ? { method: "totp", code: compact } : { method: "recovery", code: code.trim() },
  });
  if (verify.status !== 200 || !verify.body?.access_token) throw new Error(`Two-factor sign-in failed: HTTP ${verify.status}`);
  return verify.body.access_token;
}

// === The agent's side: the MCP server over stdio ===

// Browser openers that always fail: this script is the browser
const noBrowser = mkdtempSync(join(tmpdir(), "cpmesh-e2e-no-browser-"));
for (const opener of ["xdg-open", "open"]) writeFileSync(join(noBrowser, opener), "#!/bin/sh\nexit 3\n", { mode: 0o755 });

const pending = new Map();
let nextId = 1;
function start() {
  const child = spawn(process.execPath, [join(root, "dist", "index.js")], {
    stdio: ["pipe", "pipe", "pipe"],
    // No inherited server URL: the agent passes it
    env: { ...process.env, CPMESH_SERVER_URL: "", PATH: `${noBrowser}${delimiter}${process.env.PATH ?? ""}` },
  });
  child.stderr.on("data", (data) => process.stderr.write("[server] " + data));
  let buf = "";
  child.stdout.on("data", (data) => {
    buf += data.toString();
    let index;
    while ((index = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, index);
      buf = buf.slice(index + 1);
      if (!line.trim()) continue;
      const message = JSON.parse(line);
      if (message.id !== undefined && pending.has(message.id)) {
        pending.get(message.id)(message);
        pending.delete(message.id);
      }
    }
  });
  return child;
}
let proc = start();

const request = (method, params) => {
  const id = nextId++;
  proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  return new Promise((resolve) => pending.set(id, resolve));
};
const notify = (method, params) =>
  proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");
const callTool = (name, args) =>
  request("tools/call", { name, arguments: args });
async function initialize(name) {
  const init = await request("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name, version: "0" },
  });
  notify("notifications/initialized");
  return init;
}

let failures = 0;
const check = (name, ok, extra = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? " — " + extra : ""}`);
  if (!ok) failures++;
};
const textOf = (res) => res.result?.content?.[0]?.text ?? "";
const dataOf = (res) => {
  const text = textOf(res);
  return JSON.parse(text.slice(text.indexOf("{")));
};
function stop(message) {
  console.error(`\n${message}\n`);
  proc.kill();
  process.exit(1);
}

/** The agent asks to sign in; the user approves `scope` on the approval page. */
async function authorizeAgent(webToken, scope, label) {
  const login = await callTool("cpmesh_login", { server_url: serverUrl, mode: "device" });
  if (login.result?.isError) stop(textOf(login));
  const started = dataOf(login);
  check(`${label}: cpmesh_login returns at once with a link and code`,
    started.status === "authorization_pending" && /^[A-Z]{4}-[A-Z]{4}$/.test(started.user_code ?? "") &&
      started.verification_uri_complete === `${serverUrl}/activate?user_code=${started.user_code}`,
    started.message?.slice(0, 100));

  const lookup = await web(`/api/oauth/device?user_code=${encodeURIComponent(started.user_code)}`, { token: webToken });
  check(`${label}: the approval page shows the agent's request`,
    lookup.status === 200 && /^e2e-smoke\S* via cpmesh-mcp on /.test(lookup.body?.agent_name ?? "") &&
      lookup.body?.scopes?.length === 4 && /^cpmesh-mcp\/\d+\.\d+\.\d+ /.test(lookup.body?.user_agent ?? ""),
    `${lookup.status} ${lookup.body?.agent_name ?? JSON.stringify(lookup.body)}`);
  const approve = await web("/api/oauth/device/approve", { method: "POST", token: webToken, body: { user_code: started.user_code, scope } });
  check(`${label}: the user approves ${scope}`, approve.status === 200 && approve.body?.status === "approved",
    `${approve.status} ${JSON.stringify(approve.body)}`);

  const waited = await callTool("cpmesh_wait_for_approval", { timeout_seconds: 60 });
  if (waited.result?.isError) stop(textOf(waited));
  return dataOf(waited);
}

/** The agent asks to sign in through the browser; this script is the browser and the user approves `scope`. */
async function authorizeInBrowser(webToken, scope, label) {
  const login = await callTool("cpmesh_login", { server_url: serverUrl, mode: "browser" });
  if (login.result?.isError) stop(textOf(login));
  const started = dataOf(login);
  const authorize = new URL(started.verification_uri ?? "about:blank");
  check(`${label}: cpmesh_login returns the approval page for a browser on this computer`,
    started.status === "authorization_pending" && started.mode === "browser" && started.browser_opened === false &&
      `${authorize.origin}${authorize.pathname}` === `${serverUrl}/oauth/authorize` && !authorize.searchParams.has("scope") &&
      authorize.searchParams.get("code_challenge_method") === "S256" &&
      /^http:\/\/127\.0\.0\.1:\d+\/callback$/.test(authorize.searchParams.get("redirect_uri") ?? ""),
    started.message?.slice(0, 100));

  // The server checks the request and sends the browser to the consent page
  const consent = await fetch(authorize, { redirect: "manual", signal: AbortSignal.timeout(15_000) });
  const location = consent.headers.get("location") ?? "";
  const request = new URLSearchParams(location.slice(location.indexOf("?") + 1));
  check(`${label}: the server sends the browser to the consent page with every scope offered`,
    consent.status === 302 && location.startsWith("/#/authorize?") &&
      request.get("scope") === "clipboard:read clipboard:write clipboard:delete devices:manage", location.slice(0, 80));

  // The consent page: the user approves `scope`; the browser follows the answer to the agent
  const field = (name) => request.get(name) ?? "";
  const decision = await web("/api/oauth/authorize", {
    method: "POST", token: webToken,
    body: {
      client_id: field("client_id"), redirect_uri: field("redirect_uri"), state: field("state"),
      code_challenge: field("code_challenge"), code_challenge_method: field("code_challenge_method"),
      scope, agent_name: field("agent_name"), decision: "approve",
    },
  });
  check(`${label}: the user approves ${scope}`, decision.status === 200 && typeof decision.body?.redirect_to === "string",
    `${decision.status} ${JSON.stringify(decision.body)}`);
  const callback = await fetch(decision.body.redirect_to, { signal: AbortSignal.timeout(15_000) });
  check(`${label}: the agent receives the answer on 127.0.0.1`, callback.status === 200 && /cpmesh is connected/.test(await callback.text()));

  const waited = await callTool("cpmesh_wait_for_approval", { timeout_seconds: 60 });
  if (waited.result?.isError) stop(textOf(waited));
  return dataOf(waited);
}

const timeout = setTimeout(() => {
  console.error("TIMEOUT: e2e did not finish in 180s");
  proc.kill();
  process.exit(1);
}, 180_000);

try {
  const webToken = await webSignIn();
  check("the user signs in to the web API (password and second factor)", typeof webToken === "string");

  const init = await initialize("e2e-smoke");
  check("initialize", init.result?.serverInfo?.name === "cpmesh");

  // 1. Sign in: the agent asks, the user approves in the browser
  const approved = await authorizeAgent(webToken, "clipboard:read clipboard:write", "sign-in");
  if (approved.status === "pending") {
    stop("Device pending approval (account has existing devices). Finish pairing interactively via cpmesh_wait_for_approval, or use a fresh account.");
  }
  check("first-device approval bootstraps authenticated keys", approved.approved === true, approved.message?.slice(0, 100));
  const signedIn = dataOf(await callTool("cpmesh_status", {}));
  check("status shows the grant and its scopes",
    signedIn.logged_in === true && typeof signedIn.grant_id === "string" && signedIn.scope === "clipboard:read clipboard:write");

  // 2. Push a clip
  const marker = `cpmesh-mcp e2e ${new Date().toISOString()}`;
  const requestId = randomUUID();
  const push = await callTool("cpmesh_push_clipboard", { text: marker, request_id: requestId });
  check("push clipboard", push.result?.isError !== true,
    textOf(push).split("\n")[0]);
  const pushed = dataOf(push);
  check("push means persisted, not delivered", pushed.persisted === true && pushed.delivery === "unconfirmed" && typeof pushed.entry_id === "string");
  const retry = await callTool("cpmesh_push_clipboard", { text: marker, request_id: requestId });
  check("retry reconciles to the canonical entry ID", dataOf(retry).entry_id === pushed.entry_id);

  // Restart the actual published executable, retaining its encrypted keyring/session.
  const exited = once(proc, "exit");
  proc.stdin.end();
  const exitDeadline = setTimeout(() => proc.kill("SIGKILL"), 5000);
  await exited;
  clearTimeout(exitDeadline);
  check("stdio disconnect closes the relay transport", proc.signalCode === null);
  proc = start();
  await initialize("e2e-smoke-restart");

  // 3. Read latest back decrypted
  const resumedRetry = await callTool("cpmesh_push_clipboard", { text: marker, request_id: requestId });
  check("idempotent retry survives process restart", dataOf(resumedRetry).entry_id === pushed.entry_id);
  const latest = await callTool("cpmesh_get_latest_clipboard", {});
  check(
    "read back decrypted after process restart",
    textOf(latest).includes(marker),
    textOf(latest).slice(0, 80),
  );

  // 4. Search
  const search = await callTool("cpmesh_search_clipboard", {
    query: "cpmesh-mcp e2e",
  });
  check("search history", textOf(search).includes(marker));

  // 5. Devices
  const devices = await callTool("cpmesh_list_devices", {});
  check("list devices", /"devices"/.test(textOf(devices)));
  const agentDevice = signedIn.device_id;

  // 6. Status
  const status = await callTool("cpmesh_status", {});
  check(
    "status ready",
    /Ready/.test(textOf(status)) || /group_key_available": true/.test(textOf(status)),
  );

  // 7. Connected agents on the dashboard
  const grants = await web("/api/oauth/grants", { token: webToken });
  check("the dashboard lists the agent with its device",
    grants.status === 200 && grants.body?.length === 1 && grants.body[0].id === signedIn.grant_id &&
      grants.body[0].device?.id === agentDevice && grants.body[0].status === "active",
    JSON.stringify(grants.body?.[0] ?? grants.body)?.slice(0, 160));

  // 8. Re-authorize as send-only: the same device moves to the new grant, no new pairing
  const reauthorized = process.platform === "win32"
    ? await authorizeAgent(webToken, "clipboard:write", "re-authorization")
    : await authorizeInBrowser(webToken, "clipboard:write", "re-authorization in the browser");
  check("re-authorization keeps the device approved", reauthorized.approved === true, reauthorized.message?.slice(0, 100));
  const sendOnly = dataOf(await callTool("cpmesh_status", {}));
  check("the device and its keys are kept under the new grant",
    sendOnly.device_id === agentDevice && sendOnly.grant_id !== signedIn.grant_id && sendOnly.scope === "clipboard:write");
  const refused = await callTool("cpmesh_get_clipboard", {});
  check("a send-only agent cannot read and is told how to get read access",
    refused.result?.isError === true && /read access/.test(textOf(refused)) && /cpmesh_login/.test(textOf(refused)),
    textOf(refused).slice(0, 100));
  const sent = await callTool("cpmesh_push_clipboard", { text: `${marker} (send-only)` });
  check("a send-only agent can still push", sent.result?.isError !== true && dataOf(sent).persisted === true, textOf(sent).split("\n")[0]);
  const superseded = await web("/api/oauth/grants", { token: webToken });
  check("the previous authorization was replaced",
    superseded.body?.length === 1 && superseded.body[0].id === sendOnly.grant_id && superseded.body[0].scopes.join(" ") === "clipboard:write");

  // 9. Sign out: revokes the agent, which removes its device
  const logout = await callTool("cpmesh_logout", {});
  check("logout revokes the authorization", logout.result?.isError !== true && /revoked on the server/.test(textOf(logout)), textOf(logout).split("\n")[0]);
  const statusAfter = await callTool("cpmesh_status", {});
  check("logout wipes session", /"logged_in": false/.test(textOf(statusAfter)));
  const left = await web("/api/oauth/grants", { token: webToken });
  const remaining = await web("/api/devices", { token: webToken });
  check("the agent and its device are gone from the account",
    left.status === 200 && left.body?.length === 0 && remaining.status === 200 && !remaining.body?.some((d) => d.id === agentDevice));
} catch (e) {
  console.error("e2e crashed:", e);
  failures++;
} finally {
  clearTimeout(timeout);
  proc.kill();
  rmSync(noBrowser, { recursive: true, force: true });
}

process.exit(failures === 0 ? 0 : 1);
