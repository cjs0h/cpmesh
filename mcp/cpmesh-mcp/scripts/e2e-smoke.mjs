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
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const [serverUrl, username, password, code] = process.argv.slice(2);
if (!serverUrl || !username || !password) {
  console.error("Usage: node scripts/e2e-smoke.mjs <server-url> <username> <password> [code]");
  process.exit(1);
}

const proc = spawn(process.execPath, [join(root, "dist", "index.js")], {
  stdio: ["pipe", "pipe", "pipe"],
});
proc.stderr.on("data", (d) => process.stderr.write("[server] " + d));

let buf = "";
const pending = new Map();
let nextId = 1;
proc.stdout.on("data", (d) => {
  buf += d.toString();
  let idx;
  while ((idx = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, idx);
    buf = buf.slice(idx + 1);
    if (!line.trim()) continue;
    const msg = JSON.parse(line);
    if (msg.id !== undefined && pending.has(msg.id)) {
      pending.get(msg.id)(msg);
      pending.delete(msg.id);
    }
  }
});

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

  // 2. Push a clip
  const marker = `cpmesh-mcp e2e ${new Date().toISOString()}`;
  const push = await callTool("cpmesh_push_clipboard", { text: marker });
  check("push clipboard", push.result?.isError !== true,
    textOf(push).split("\n")[0]);

  // 3. Read latest back decrypted
  const latest = await callTool("cpmesh_get_latest_clipboard", {});
  check(
    "read back decrypted",
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
