#!/usr/bin/env node
/**
 * End-to-end smoke test: drives the built MCP server (dist/index.js) over
 * stdio exactly like a real MCP client would, against a live cpmesh server.
 *
 * Registers/logs in as a device, pushes a clipboard entry, reads it back
 * decrypted, searches history, lists devices, checks status, and logs out.
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
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const [
  serverUrl = process.env.CPMESH_E2E_URL,
  username = process.env.CPMESH_E2E_USERNAME,
  password = process.env.CPMESH_E2E_PASSWORD,
  code = process.env.CPMESH_E2E_CODE,
] = process.argv.slice(2);
if (!serverUrl || !username || !password) {
  console.error("Usage: node scripts/e2e-smoke.mjs <server-url> <username> <password> [code]");
  process.exit(1);
}

const pending = new Map();
let nextId = 1;
function start() {
  const process = spawn(globalThis.process.execPath, [join(root, "dist", "index.js")], {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...globalThis.process.env, CPMESH_SERVER_URL: "", CPMESH_USERNAME: "", CPMESH_PASSWORD: "" },
  });
  process.stderr.on("data", (data) => globalThis.process.stderr.write("[server] " + data));
  let buf = "";
  process.stdout.on("data", (data) => {
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
  return process;
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

let failures = 0;
const check = (name, ok, extra = "") => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${extra ? " — " + extra : ""}`);
  if (!ok) failures++;
};
const textOf = (res) => res.result?.content?.[0]?.text ?? "";

const timeout = setTimeout(() => {
  console.error("TIMEOUT: e2e did not finish in 120s");
  proc.kill();
  process.exit(1);
}, 120_000);

try {
  const init = await request("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "e2e-smoke", version: "0" },
  });
  check("initialize", init.result?.serverInfo?.name === "cpmesh");
  notify("notifications/initialized");

  // 1. Login
  const login = await callTool("cpmesh_login", {
    server_url: serverUrl,
    username,
    password,
    ...(code && { code }),
  });
  if (login.result?.isError) {
    console.error(`\n${textOf(login)}\n`);
    proc.kill();
    process.exit(1);
  }
  const loginData = JSON.parse(
    textOf(login).slice(textOf(login).indexOf("{")),
    {},
  );
  if (loginData.status === "mfa_required") {
    console.error(
      "\nThe account uses two-factor authentication: re-run with the current 6-digit code " +
        "from the authenticator app (or a recovery code) as the fourth argument.\n",
    );
    proc.kill();
    process.exit(1);
  }
  check("login", loginData.status === "approved" || loginData.status === "pending",
    loginData.message?.slice(0, 100));

  if (loginData.status !== "approved") {
    console.error(
      "\nDevice pending approval (account has existing devices). Finish pairing " +
        "interactively via cpmesh_wait_for_approval, or use a fresh account.\n",
    );
    proc.kill();
    process.exit(1);
  }
  const approved = await callTool("cpmesh_wait_for_approval", { timeout_seconds: 5 });
  check("first-device approval bootstraps authenticated keys", approved.result?.isError !== true && /"approved": true/.test(textOf(approved)));

  // 2. Push a clip
  const marker = `cpmesh-mcp e2e ${new Date().toISOString()}`;
  const requestId = randomUUID();
  const push = await callTool("cpmesh_push_clipboard", { text: marker, request_id: requestId });
  check("push clipboard", push.result?.isError !== true,
    textOf(push).split("\n")[0]);
  const pushed = JSON.parse(textOf(push).slice(textOf(push).indexOf("{")));
  check("push means persisted, not delivered", pushed.persisted === true && pushed.delivery === "unconfirmed" && typeof pushed.entry_id === "string");
  const retry = await callTool("cpmesh_push_clipboard", { text: marker, request_id: requestId });
  const retried = JSON.parse(textOf(retry).slice(textOf(retry).indexOf("{")));
  check("retry reconciles to the canonical entry ID", retried.entry_id === pushed.entry_id);

  // Restart the actual published executable, retaining its encrypted keyring/session.
  const exited = once(proc, "exit");
  proc.stdin.end();
  const exitDeadline = setTimeout(() => proc.kill("SIGKILL"), 5000);
  await exited;
  clearTimeout(exitDeadline);
  check("stdio disconnect closes the relay transport", proc.signalCode === null);
  proc = start();
  await request("initialize", {
    protocolVersion: "2024-11-05", capabilities: {},
    clientInfo: { name: "e2e-smoke-restart", version: "0" },
  });
  notify("notifications/initialized");

  // 3. Read latest back decrypted
  const resumedRetry = await callTool("cpmesh_push_clipboard", { text: marker, request_id: requestId });
  const resumedReceipt = JSON.parse(textOf(resumedRetry).slice(textOf(resumedRetry).indexOf("{")));
  check("idempotent retry survives process restart", resumedReceipt.entry_id === pushed.entry_id);
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

  // 6. Status
  const status = await callTool("cpmesh_status", {});
  check(
    "status ready",
    /Ready/.test(textOf(status)) || /group_key_available": true/.test(textOf(status)),
  );

  // 7. Logout wipes state
  const logout = await callTool("cpmesh_logout", {});
  const statusAfter = await callTool("cpmesh_status", {});
  check("logout wipes session", /"logged_in": false/.test(textOf(statusAfter)));
} catch (e) {
  console.error("e2e crashed:", e);
  failures++;
} finally {
  clearTimeout(timeout);
  proc.kill();
}

process.exit(failures === 0 ? 0 : 1);
