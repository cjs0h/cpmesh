#!/usr/bin/env node
// Runs only against an explicitly supplied, disposable loopback database.
//
// Starts the relay (with BASE_URL, so agents can sign in), creates an account
// that must use two-factor authentication and enrolls its authenticator, then
// runs e2e-smoke.mjs: the harness signs the user in through the web API and
// approves the MCP server's device-flow sign-in like the dashboard does.
import { generateKeyPairSync, randomBytes, createHmac } from "node:crypto";
import { mkdtemp, mkdir, writeFile, rm, truncate } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "node:net";
import { once } from "node:events";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";

const database = process.env.CPMESH_E2E_DATABASE_URL;
if (!database) throw new Error("Set CPMESH_E2E_DATABASE_URL to a disposable loopback database named cpmesh_e2e*");
const parsed = new URL(database);
if (!["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname) || !parsed.pathname.startsWith("/cpmesh_e2e")) {
  throw new Error("Refusing a non-loopback or non-test database");
}
const directory = await mkdtemp(join(tmpdir(), "cpmesh-live-smoke-"));
const root = fileURLToPath(new URL("../../../", import.meta.url));
const binary = resolve(process.env.CPMESH_E2E_SERVER ?? join(root, "target/debug/cpmesh-server"));
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});
await Promise.all([
  writeFile(join(directory, "private.pem"), privateKey, { mode: 0o600 }),
  writeFile(join(directory, "public.json"), JSON.stringify([{ kid: "e2e", pem: publicKey }])),
  writeFile(join(directory, ".env"), "# Isolated test configuration; never load a parent .env\n"),
  mkdir(join(directory, "downloads")),
]);
const reservation = createServer();
reservation.listen(0, "127.0.0.1");
await once(reservation, "listening");
const port = reservation.address().port;
await new Promise((done) => reservation.close(done));
const url = `http://127.0.0.1:${port}`;
const username = `e2e-${randomBytes(6).toString("hex")}`;
const password = `Test-${randomBytes(20).toString("hex")}!`;
const relay = spawn(binary, [], {
  cwd: directory,
  env: {
    PATH: process.env.PATH, HOME: directory, DATABASE_URL: database,
    JWT_ACTIVE_KID: "e2e",
    JWT_PRIVATE_KEY_PATH: join(directory, "private.pem"),
    JWT_PUBLIC_KEYS_PATH: join(directory, "public.json"),
    PII_MASTER_KEY: randomBytes(32).toString("base64"),
    PII_HMAC_KEY: randomBytes(32).toString("base64"),
    INITIAL_ADMIN: username, INITIAL_ADMIN_PASSWORD: password,
    INITIAL_ADMIN_EMAIL: `${username}@example.invalid`,
    ADDR: `127.0.0.1:${port}`, BASE_URL: url,
    DOWNLOADS_DIR: join(directory, "downloads"),
    REGISTRATION_OPEN: "false", MFA_REQUIRED: "all", RUST_LOG: "warn",
  },
  stdio: ["ignore", "ignore", "pipe"],
});
let startupError;
let relayLog = "";
relay.on("error", (error) => { startupError = error; });
relay.stderr.on("data", (data) => { relayLog = (relayLog + data).slice(-16000); });
const delay = (ms) => new Promise((done) => setTimeout(done, ms));

async function post(path, body, token) {
  const response = await fetch(url + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(token && { Authorization: "Bearer " + token }) },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15000),
  });
  return { status: response.status, body: await response.json() };
}
function totp(secret) {
  let bits = 0, value = 0;
  const bytes = [];
  for (const character of secret) {
    const digit = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(character);
    if (digit < 0) throw new Error("Invalid TOTP fixture secret");
    value = (value << 5) | digit;
    bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((value >>> bits) & 255); }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  return ((digest.readUInt32BE(digest[19] & 15) & 0x7fffffff) % 1000000).toString().padStart(6, "0");
}

try {
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    if (startupError || relay.exitCode !== null) throw startupError ?? new Error(`Relay exited: ${relayLog}`);
    try { ready = (await fetch(url + "/api/auth/social/status", { signal: AbortSignal.timeout(500) })).ok; }
    catch { /* The child has not bound its loopback listener yet. */ }
    if (ready) break;
    await delay(100);
  }
  if (!ready) throw new Error(`Relay readiness deadline: ${relayLog}`);
  const login = await post("/api/auth/login", { username, password });
  if (login.status !== 403 || login.body.stage !== "enroll") throw new Error(`Expected mandatory MFA enrollment, got HTTP ${login.status}`);
  const setup = await post("/api/mfa/totp/setup", {}, login.body.mfa_token);
  if (setup.status !== 200) throw new Error(`TOTP setup failed: HTTP ${setup.status}`);
  const enabled = await post("/api/mfa/totp/enable", { code: totp(setup.body.secret) }, login.body.mfa_token);
  if (enabled.status !== 200 || !enabled.body.recovery_codes?.[0]) throw new Error("TOTP enrollment failed");
  const test = spawn(process.execPath, [fileURLToPath(new URL("./e2e-smoke.mjs", import.meta.url))], {
    stdio: "inherit",
    env: {
      ...process.env, CPMESH_HOME: join(directory, "mcp"), CPMESH_SERVER_URL: "",
      CPMESH_E2E_URL: url, CPMESH_E2E_USERNAME: username, CPMESH_E2E_PASSWORD: password,
      CPMESH_E2E_CODE: enabled.body.recovery_codes[0],
    },
  });
  const [code] = await once(test, "exit");
  if (code !== 0) throw new Error(`Live MCP smoke failed (exit ${code})`);
  if (process.platform !== "win32") {
    const file = join(directory, "downloads", "stream-probe.bin");
    await writeFile(file, "");
    await truncate(file, 128 * 1024 * 1024);
    const rss = async () => Number((await promisify(execFile)("ps", ["-o", "rss=", "-p", String(relay.pid)])).stdout.trim());
    const baseline = await rss();
    const downloads = await Promise.all([fetch(url + "/api/downloads/stream-probe.bin"), fetch(url + "/api/downloads/stream-probe.bin")]);
    let peak = baseline;
    try {
      for (const response of downloads) {
        if (response.status !== 200 || Number(response.headers.get("content-length")) !== 128 * 1024 * 1024) throw new Error("Streaming fixture failed");
      }
      for (let sample = 0; sample < 10; sample++) { peak = Math.max(peak, await rss()); await delay(100); }
      console.log(`Streaming probe: two stalled 128 MiB downloads; baseline ${baseline} KiB, peak ${peak} KiB, delta ${peak - baseline} KiB`);
      if (peak - baseline >= 64 * 1024) throw new Error("Installer responses exceeded the bounded-memory regression threshold");
    } finally {
      await Promise.all(downloads.map((response) => response.body?.cancel()));
    }
  }
} finally {
  if (relay.exitCode === null && !startupError) {
    const exited = once(relay, "exit");
    relay.kill("SIGTERM");
    const deadline = setTimeout(() => relay.kill("SIGKILL"), 3000);
    await exited;
    clearTimeout(deadline);
  }
  await rm(directory, { recursive: true, force: true });
}
