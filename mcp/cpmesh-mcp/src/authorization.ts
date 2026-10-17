/**
 * Signing this agent in, one sign-in at a time:
 *
 * - Browser on this computer: authorization code with PKCE and a loopback
 *   redirect. The listener lives in this process; the code is exchanged as soon
 *   as the callback arrives (codes last 120 s).
 * - Device authorization (RFC 8628): the user enters a code in any browser.
 *   The pending request is saved in authorization.json (0600), so a restarted
 *   MCP server keeps polling it; processes sharing the profile share its
 *   polling schedule under the state lock, so they never poll too often.
 *
 * Approved tokens are saved (stage "authorized") before they are returned, so
 * an approval is not lost when registering the device fails or the process
 * stops; the device registration then removes the file.
 */

import { detectSignInMode, openBrowser, type ModeChoice, type SignInMode } from "./browser.js";
import { AuthorizationError, startLoopback, type Loopback } from "./loopback.js";
import {
  OAuthError,
  authorizationUrl,
  discover,
  exchangeCode,
  pkcePair,
  pollDeviceCode,
  randomState,
  requestDeviceAuthorization,
  revokeToken,
  sameServer,
  type ServerMetadata,
  type TokenSet,
} from "./oauth.js";
import {
  clearAuthorization,
  loadAuthorization,
  saveAuthorization,
  withStateLock,
  type AuthorizedTokens,
  type PendingDeviceAuthorization,
} from "./state.js";

/** How long a browser sign-in waits for its callback. */
export const BROWSER_TIMEOUT_MS = 10 * 60_000;
/** A sign-in about to expire is started again rather than shown once more. */
const MIN_REMAINING_MS = 60_000;

/** A sign-in waiting for the user's approval, as the agent shows it. */
export interface PendingAuthorization {
  status: "authorization_pending";
  mode: SignInMode;
  server_url: string;
  /** Browser: the approval page, on this computer. Device: where to enter the code. */
  verification_uri: string;
  /** Device: the same page with the code filled in. */
  verification_uri_complete?: string;
  /** Device: the code the page must show. */
  user_code?: string;
  expires_at: string;
  /** Browser: whether this MCP server opened the page itself. */
  browser_opened?: boolean;
  /** Why the device flow was chosen automatically. */
  reason?: string;
}

/** Approved: the tokens, saved until the device registers with them. */
export interface Authorized {
  status: "authorized";
  server_url: string;
  tokens: TokenSet;
}

export interface AuthorizationFailed {
  status: "access_denied" | "expired_token" | "failed";
  message: string;
}

export type AuthorizationState = PendingAuthorization | Authorized | AuthorizationFailed;

/** What `peek` reports: a pending sign-in, or an approved one whose device has not registered yet. */
export type SignInProgress = PendingAuthorization | { status: "authorized"; server_url: string };

interface BrowserFlow {
  server_url: string;
  authorize_url: string;
  expires_at: number;
  opened: boolean;
  loopback: Loopback;
  /** Resolves once the callback arrived and its code was exchanged and saved. */
  tokens: Promise<TokenSet>;
  outcome?: { tokens: TokenSet } | { error: Error };
  cancelled: boolean;
}

export interface AuthorizerOptions {
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  detect?: () => ModeChoice;
  open?: (url: string) => Promise<boolean>;
  browserTimeoutMs?: number;
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export class Authorizer {
  private browser: BrowserFlow | null = null;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly detect: () => ModeChoice;
  private readonly open: (url: string) => Promise<boolean>;
  private readonly browserTimeoutMs: number;

  constructor(options: AuthorizerOptions = {}) {
    this.now = options.now ?? Date.now;
    this.sleep = options.sleep ?? sleep;
    this.detect = options.detect ?? (() => detectSignInMode());
    this.open = options.open ?? ((url) => openBrowser(url));
    this.browserTimeoutMs = options.browserTimeoutMs ?? BROWSER_TIMEOUT_MS;
  }

  /**
   * Starts a sign-in and returns at once with what to show the user. A sign-in
   * still waiting for the same server (and mode, unless `auto`) is shown again
   * instead, so the user never sees two codes.
   */
  async start(request: { serverUrl: string; mode: "auto" | SignInMode; agentName: string }): Promise<PendingAuthorization> {
    const current = this.peek();
    if (
      current?.status === "authorization_pending" &&
      sameServer(current.server_url, request.serverUrl) &&
      (request.mode === "auto" || request.mode === current.mode) &&
      Date.parse(current.expires_at) - this.now() >= MIN_REMAINING_MS
    ) {
      if (current.mode === "browser" && this.browser) {
        this.browser.opened = await this.open(this.browser.authorize_url);
        return this.browserView(this.browser);
      }
      return current;
    }

    const metadata = await discover(request.serverUrl);
    await this.cancel();
    let choice: ModeChoice = request.mode === "auto" ? this.detect() : { mode: request.mode };
    if (choice.mode === "browser") {
      const flow = await this.startBrowser(metadata, request.agentName);
      flow.opened = await this.open(flow.authorize_url);
      if (flow.opened || request.mode === "browser") {
        this.browser = flow;
        return this.browserView(flow);
      }
      flow.cancelled = true;
      flow.loopback.close();
      choice = { mode: "device", reason: "the browser could not be opened on this computer" };
    }

    const device = await requestDeviceAuthorization(metadata, request.agentName);
    const now = this.now();
    const interval = device.interval ?? 5;
    const pending: PendingDeviceAuthorization = {
      stage: "pending",
      server_url: metadata.server_url,
      token_endpoint: metadata.token_endpoint,
      device_code: device.device_code,
      user_code: device.user_code,
      verification_uri: device.verification_uri,
      ...(device.verification_uri_complete !== undefined && { verification_uri_complete: device.verification_uri_complete }),
      expires_at: now + device.expires_in * 1000,
      interval,
      next_poll_at: now + interval * 1000,
      created_at: new Date(now).toISOString(),
    };
    await withStateLock(() => saveAuthorization(pending));
    return { ...deviceView(pending), ...(choice.reason !== undefined && { reason: choice.reason }) };
  }

  /** The sign-in in progress, without waiting or polling. */
  peek(): SignInProgress | null {
    const stored = loadAuthorization();
    if (stored?.stage === "authorized") return { status: "authorized", server_url: stored.server_url };
    // A finished browser sign-in is reported by `complete`, never shown again
    if (this.browser && !this.browser.outcome) return this.browserView(this.browser);
    return stored ? deviceView(stored) : null;
  }

  /**
   * Waits until `deadline` (Unix ms; now = no waiting) for the sign-in in
   * progress: the browser's callback, or the device code's approval (polled at
   * the server's pace). Null when no sign-in is in progress.
   */
  async complete(deadline: number): Promise<AuthorizationState | null> {
    const stored = loadAuthorization();
    if (stored?.stage === "authorized") return authorizedState(stored);
    if (this.browser) return this.completeBrowser(this.browser, deadline);
    if (stored?.stage === "pending") return this.pollDevice(deadline);
    return null;
  }

  /**
   * Abandons the sign-in in progress. Approved tokens that no device used yet
   * are revoked. Pass `locked` when the caller holds the state lock.
   */
  async cancel(options: { locked?: boolean } = {}): Promise<void> {
    this.stop();
    const work = async () => {
      const stored = loadAuthorization();
      if (stored?.stage === "authorized") {
        await revokeWithRetry(stored.server_url, stored.refresh_token).catch((error: unknown) => {
          console.error("[cpmesh-mcp] Could not revoke an unused sign-in:", error instanceof Error ? error.message : String(error));
        });
      }
      clearAuthorization();
    };
    await (options.locked ? work() : withStateLock(work));
  }

  /** Stops waiting for a browser callback (when the MCP connection closes). Saved state stays. */
  stop(): void {
    const flow = this.browser;
    this.browser = null;
    if (flow) {
      flow.cancelled = true;
      flow.loopback.close();
    }
  }

  // === Browser on this computer ===

  private async startBrowser(metadata: ServerMetadata, agentName: string): Promise<BrowserFlow> {
    const state = randomState();
    const { verifier, challenge } = pkcePair();
    const loopback = await startLoopback({ state, issuer: metadata.issuer, timeoutMs: this.browserTimeoutMs });
    const flow: BrowserFlow = {
      server_url: metadata.server_url,
      authorize_url: authorizationUrl(metadata, { redirectUri: loopback.redirectUri, state, challenge, agentName }),
      expires_at: this.now() + this.browserTimeoutMs,
      opened: false,
      loopback,
      tokens: Promise.resolve(undefined as never),
      cancelled: false,
    };
    flow.tokens = loopback.code.then(async (code) => {
      // The code lasts 120 s: exchange it now, whether or not anyone is waiting
      const tokens = await this.exchange(metadata, code, loopback.redirectUri, verifier);
      const kept = await withStateLock(() => {
        if (flow.cancelled) return false;
        saveAuthorization(authorizedRecord(metadata.server_url, tokens, this.now()));
        return true;
      });
      if (!kept) {
        await revokeWithRetry(metadata.server_url, tokens.refresh_token).catch(() => undefined);
        throw new AuthorizationError("cancelled", "The sign-in was cancelled.");
      }
      return tokens;
    });
    flow.tokens.then(
      (tokens) => {
        flow.outcome = { tokens };
      },
      (error: unknown) => {
        flow.outcome = { error: error instanceof Error ? error : new Error(String(error)) };
      },
    );
    return flow;
  }

  private async exchange(metadata: ServerMetadata, code: string, redirectUri: string, verifier: string): Promise<TokenSet> {
    for (let attempt = 0; ; attempt++) {
      try {
        return await exchangeCode(metadata.token_endpoint, code, redirectUri, verifier);
      } catch (error) {
        if (!(error instanceof OAuthError)) throw error;
        // A lost answer is retried at once: if the code was used, the server says so (invalid_grant)
        const retry = attempt < 3 && (error.transient || (error.status === 0 && attempt === 0));
        if (retry) {
          await this.sleep(Math.min((error.extra.retryAfter ?? 1) * 1000, 10_000));
          continue;
        }
        throw new AuthorizationError(error.error, `The sign-in could not be completed (${error.description}).`);
      }
    }
  }

  private async completeBrowser(flow: BrowserFlow, deadline: number): Promise<AuthorizationState> {
    const wait = deadline - this.now();
    if (!flow.outcome && wait > 0) await settledOrTimeout(flow.tokens, wait);
    if (!flow.outcome) return this.browserView(flow);
    // The outcome is reported once; approved tokens are saved for the registration
    if (this.browser === flow) this.browser = null;
    if ("tokens" in flow.outcome) return { status: "authorized", server_url: flow.server_url, tokens: flow.outcome.tokens };
    return failure(flow.outcome.error);
  }

  private browserView(flow: BrowserFlow): PendingAuthorization {
    return {
      status: "authorization_pending",
      mode: "browser",
      server_url: flow.server_url,
      verification_uri: flow.authorize_url,
      expires_at: new Date(flow.expires_at).toISOString(),
      browser_opened: flow.opened,
    };
  }

  // === Device authorization ===

  private async pollDevice(deadline: number): Promise<AuthorizationState | null> {
    for (;;) {
      const step = await withStateLock(() => this.pollOnce());
      if (step.kind === "done") return step.state;
      if (step.waitUntil > deadline) return deviceView(step.pending);
      await this.sleep(Math.max(0, step.waitUntil - this.now()));
    }
  }

  /** Polls the saved device code once if it is due (under the state lock). */
  private async pollOnce(): Promise<
    | { kind: "done"; state: AuthorizationState | null }
    | { kind: "wait"; waitUntil: number; pending: PendingDeviceAuthorization }
  > {
    const stored = loadAuthorization();
    if (!stored) return { kind: "done", state: null };
    if (stored.stage === "authorized") return { kind: "done", state: authorizedState(stored) };
    const done = (state: AuthorizationState) => {
      clearAuthorization();
      return { kind: "done" as const, state };
    };
    if (this.now() >= stored.expires_at) return done(EXPIRED);
    if (this.now() < stored.next_poll_at) return { kind: "wait", waitUntil: stored.next_poll_at, pending: stored };

    const reschedule = (interval: number, seconds = interval) => {
      const next = { ...stored, interval, next_poll_at: this.now() + seconds * 1000 };
      saveAuthorization(next);
      return { kind: "wait" as const, waitUntil: next.next_poll_at, pending: next };
    };
    try {
      const tokens = await pollDeviceCode(stored.token_endpoint, stored.device_code);
      saveAuthorization(authorizedRecord(stored.server_url, tokens, this.now()));
      return { kind: "done", state: { status: "authorized", server_url: stored.server_url, tokens } };
    } catch (error) {
      if (!(error instanceof OAuthError)) throw error;
      switch (error.error) {
        case "authorization_pending":
          return reschedule(stored.interval);
        case "slow_down":
          // The server raised the interval (by 5 s) and expects it from now on
          return reschedule(error.extra.interval ?? stored.interval + 5);
        case "access_denied":
          return done(DENIED);
        case "expired_token":
          return done(EXPIRED);
        default:
          // The server or the network failed: poll again later
          if (error.status === 0 || error.status === 429 || error.status >= 500) {
            return reschedule(stored.interval, Math.max(stored.interval, error.extra.retryAfter ?? 0));
          }
          return done({ status: "failed", message: `The sign-in could not be completed (${error.error}: ${error.description}).` });
      }
    }
  }
}

const DENIED: AuthorizationFailed = { status: "access_denied", message: "The user denied the sign-in request." };
const EXPIRED: AuthorizationFailed = {
  status: "expired_token",
  message: "The sign-in request expired before the user approved it.",
};

function failure(error: Error): AuthorizationFailed {
  if (error instanceof AuthorizationError) {
    if (error.error === "access_denied") return { status: "access_denied", message: error.message };
    if (error.error === "timeout") return { status: "expired_token", message: error.message };
  }
  return { status: "failed", message: error.message };
}

function deviceView(pending: PendingDeviceAuthorization): PendingAuthorization {
  return {
    status: "authorization_pending",
    mode: "device",
    server_url: pending.server_url,
    verification_uri: pending.verification_uri,
    ...(pending.verification_uri_complete !== undefined && { verification_uri_complete: pending.verification_uri_complete }),
    user_code: pending.user_code,
    expires_at: new Date(pending.expires_at).toISOString(),
  };
}

function authorizedRecord(serverUrl: string, tokens: TokenSet, now: number): AuthorizedTokens {
  return {
    stage: "authorized",
    server_url: serverUrl,
    access_token: tokens.access_token,
    refresh_token: tokens.refresh_token,
    ...(tokens.scope !== undefined && { scope: tokens.scope }),
    user_id: tokens.user_id,
    grant_id: tokens.grant_id,
    created_at: new Date(now).toISOString(),
  };
}

function authorizedState(stored: AuthorizedTokens): Authorized {
  return {
    status: "authorized",
    server_url: stored.server_url,
    tokens: {
      access_token: stored.access_token,
      token_type: "Bearer",
      refresh_token: stored.refresh_token,
      ...(stored.scope !== undefined && { scope: stored.scope }),
      user_id: stored.user_id,
      grant_id: stored.grant_id,
    },
  };
}

/** Resolves when `promise` settles or after `ms`, whichever comes first. */
function settledOrTimeout(promise: Promise<unknown>, ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    const done = () => {
      clearTimeout(timer);
      resolve();
    };
    promise.then(done, done);
  });
}

/**
 * Signs this agent out on the server (RFC 7009): its grant is revoked and its
 * device removed. Retries a temporarily unavailable server briefly.
 */
export async function revokeWithRetry(serverUrl: string, refreshToken: string): Promise<void> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await revokeToken(`${serverUrl}/oauth/revoke`, refreshToken);
    } catch (error) {
      if (!(error instanceof OAuthError) || !error.transient || attempt >= 2) throw error;
      await sleep(Math.min((error.extra.retryAfter ?? 1) * 1000, 5_000));
    }
  }
}
