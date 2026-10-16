#!/usr/bin/env node
/**
 * Protocol smoke test: spawns the built server (dist/index.js) and exercises
 * the MCP surface over stdio — initialize, tools/list (including the login
 * tool's two-factor code parameter), prompts/list, a cpmesh_status call
 * (expects a graceful not-logged-in error), and the cpmesh_skill prompt.
 *
 * Usage: node scripts/smoke.mjs   (run after `npm run build`)
 * Exits non-zero on any failure.
 */

import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, dirname } from "node:path";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const home = await mkdtemp(join(tmpdir(), "cpmesh-protocol-smoke-"));
const proc = spawn(process.execPath, [join(root, "dist", "index.js")], {
  stdio: ["pipe", "pipe", "pipe"],
  env: { ...process.env, CPMESH_HOME: home, CPMESH_SERVER_URL: "", CPMESH_USERNAME: "", CPMESH_PASSWORD: "" },
});

let failures = 0;
const check = (name, ok) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok) failures++;
};

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

const timeout = setTimeout(() => {
  console.error("TIMEOUT: smoke test did not finish in 30s");
  proc.kill();
  process.exit(1);
}, 30_000);

try {
  const init = await request("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "smoke", version: "0" },
  });
  check(
    "initialize returns server info",
    init.result?.serverInfo?.name === "cpmesh",
  );

  notify("notifications/initialized");

  const tools = await request("tools/list", {});
  const toolNames = (tools.result?.tools ?? []).map((t) => t.name);
  const expected = [
    "cpmesh_status",
    "cpmesh_login",
    "cpmesh_wait_for_approval",
    "cpmesh_push_clipboard",
    "cpmesh_get_clipboard",
    "cpmesh_get_latest_clipboard",
    "cpmesh_search_clipboard",
    "cpmesh_delete_clipboard_entry",
    "cpmesh_list_devices",
    "cpmesh_remove_device",
    "cpmesh_logout",
    "cpmesh_confirm_pairing",
    "cpmesh_verify_device",
  ];
  check(
    `all ${expected.length} tools registered`,
    expected.every((n) => toolNames.includes(n)),
  );

  const loginInput = (tools.result?.tools ?? []).find((t) => t.name === "cpmesh_login")?.inputSchema;
  check(
    "cpmesh_login takes an optional two-factor code and password",
    loginInput?.properties?.code?.type === "string" &&
      !(loginInput.required ?? []).some((name) => name === "code" || name === "password"),
  );

  const prompts = await request("prompts/list", {});
  check(
    "skill prompt registered",
    (prompts.result?.prompts ?? []).some((p) => p.name === "cpmesh_skill"),
  );

  const status = await request("tools/call", {
    name: "cpmesh_status",
    arguments: {},
  });
  const statusText = status.result?.content?.[0]?.text ?? "";
  check(
    "status tool reports not-logged-in gracefully with next step",
    /cpmesh_login/.test(statusText) && /logged_in/.test(statusText),
  );

  const skill = await request("prompts/get", { name: "cpmesh_skill" });
  const skillText = skill.result?.messages?.[0]?.content?.text ?? "";
  check(
    "skill prompt has install instructions",
    skillText.includes("mcpServers") && skillText.length > 200,
  );
} catch (e) {
  console.error("smoke test crashed:", e);
  failures++;
} finally {
  clearTimeout(timeout);
  proc.kill();
  await rm(home, { recursive: true, force: true });
}

process.exit(failures === 0 ? 0 : 1);
