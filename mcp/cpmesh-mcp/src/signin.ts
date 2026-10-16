/**
 * Password sign-in with two-factor authentication.
 *
 * When an account has a second factor, the server answers a correct password
 * with a sign-in ticket (valid 10 minutes, single use) instead of tokens. The
 * MCP server cannot use passkeys, so it finishes the sign-in with a code from an
 * authenticator app (TOTP) or a recovery code. The user usually types that code
 * after being asked for it, so the ticket waits in memory for a later
 * cpmesh_login call. Tickets and codes are never logged or written to disk.
 */

import { ApiError, MfaRequiredError, type CpmeshApi } from "./api.js";
import type { AuthResponse, MfaChallenge } from "./protocol.js";

/** How long the server accepts a sign-in ticket. */
export const TICKET_LIFETIME_MS = 10 * 60_000;
/** Tickets are given up a little early, so they do not expire on the way to the server. */
const TICKET_MARGIN_MS = 15_000;

export type CodeMethod = "totp" | "recovery";

/** How to send a code the user typed: six digits come from an authenticator app. */
export function codeMethod(code: string): { method: CodeMethod; code: string } {
  const compact = code.replace(/\s+/g, "");
  return /^\d{6}$/.test(compact)
    ? { method: "totp", code: compact }
    : { method: "recovery", code: code.trim() };
}

export interface Account {
  serverUrl: string;
  username: string;
}

const sameServer = (a: string, b: string) => baseUrl(a).toLowerCase() === baseUrl(b).toLowerCase();
const sameUser = (a: string, b: string) => a.trim().toLowerCase() === b.trim().toLowerCase();

export function sameAccount(a: Account, b: Account): boolean {
  return sameServer(a.serverUrl, b.serverUrl) && sameUser(a.username, b.username);
}

function baseUrl(url: string): string {
  return url.trim().replace(/\/+$/, "");
}

export interface SignInRequest extends Account {
  password?: string;
  /** Two-factor code: six digits from an authenticator app, or a recovery code. */
  code?: string;
  deviceName: string;
}

export type SignInResult =
  | {
      status: "signed_in";
      auth: AuthResponse;
      /** Set when a recovery code was used. */
      recoveryCodesRemaining?: number;
    }
  | { status: "mfa_required"; methods: CodeMethod[]; message: string };

interface PendingSignIn extends Account {
  ticket: string;
  methods: CodeMethod[];
  expiresAt: number;
}

export class SignInFlow {
  /** The sign-in waiting for its two-factor code. */
  private pending: PendingSignIn | null = null;

  constructor(private readonly now: () => number = Date.now) {}

  /**
   * The account whose sign-in is waiting for a two-factor code, if it matches
   * `serverUrl` and `username` (either may be omitted).
   */
  waiting(serverUrl?: string, username?: string): Account | null {
    const p = this.pending;
    if (!p || p.expiresAt <= this.now()) return null;
    if (serverUrl !== undefined && !sameServer(serverUrl, p.serverUrl)) return null;
    if (username !== undefined && !sameUser(username, p.username)) return null;
    return { serverUrl: p.serverUrl, username: p.username };
  }

  /** Forgets the sign-in waiting for a code. */
  clear(): void {
    this.pending = null;
  }

  /**
   * Signs in with the password, or finishes the sign-in waiting for a code.
   * Resolves `mfa_required` when the user still has to supply a code.
   */
  async signIn(api: CpmeshApi, req: SignInRequest): Promise<SignInResult> {
    const code = req.code?.trim() ? req.code : undefined;
    const ours = this.pending !== null && sameAccount(this.pending, req) ? this.pending : null;
    const waiting = ours && ours.expiresAt > this.now() ? ours : null;
    let lapsed = ours !== null && waiting === null;
    if (lapsed) this.pending = null;

    if (waiting && code) {
      const result = await this.verify(api, waiting, code);
      if (result) return result;
      lapsed = true; // the server no longer accepts the ticket
    } else if (waiting && !req.password) {
      return this.codeNeeded(waiting);
    }

    if (!req.password) {
      throw new Error(
        lapsed
          ? "The sign-in waiting for the two-factor code has expired (it lasts 10 minutes). " +
              "Call cpmesh_login again with the password and a new code."
          : code
            ? // The account stays out of the message: tool errors are also written to the log
              "No sign-in for this account is waiting for a two-factor code: call cpmesh_login with the password and the code."
            : "No password: ask the user for their cpmesh password and pass it to cpmesh_login.",
      );
    }

    this.pending = null;
    let challenge: MfaChallenge;
    try {
      return {
        status: "signed_in",
        auth: await api.login(req.username, req.password, req.deviceName),
      };
    } catch (e) {
      if (!(e instanceof MfaRequiredError)) throw readable(e);
      challenge = e.challenge;
    }

    const next = this.keep(req, challenge);
    if (!code) return this.codeNeeded(next);
    const result = await this.verify(api, next, code);
    if (!result) {
      throw new Error("The server did not accept the new sign-in; call cpmesh_login again.");
    }
    return result;
  }

  /** Keeps the ticket of a sign-in that can be finished with a code. */
  private keep(req: SignInRequest, challenge: MfaChallenge): PendingSignIn {
    const dashboard = baseUrl(req.serverUrl);
    if (challenge.stage === "enroll") {
      throw new Error(
        `Two-factor authentication is required for this account, but it is not set up yet. ` +
          `Ask the user to sign in on the web dashboard at ${dashboard}/#/login and set up an authenticator app ` +
          `(Settings → Two-factor authentication; the MCP server cannot use passkeys), ` +
          `then call cpmesh_login again with the password and the 6-digit code from the app.`,
      );
    }
    const methods = challenge.methods.filter(
      (m): m is CodeMethod => m === "totp" || m === "recovery",
    );
    if (methods.length === 0) {
      throw new Error(
        `This account's only second factor is a passkey, which the MCP server cannot use. ` +
          `Ask the user to add an authenticator app on the web dashboard (${dashboard}/#/settings → Two-factor authentication), ` +
          `then call cpmesh_login again with the password and the 6-digit code from the app.`,
      );
    }
    this.pending = {
      serverUrl: req.serverUrl,
      username: req.username,
      ticket: challenge.mfa_token,
      methods,
      expiresAt: this.now() + TICKET_LIFETIME_MS - TICKET_MARGIN_MS,
    };
    return this.pending;
  }

  private codeNeeded(p: PendingSignIn): SignInResult {
    const ask = p.methods.includes("totp")
      ? "Ask the user for the current 6-digit code from their authenticator app" +
        (p.methods.includes("recovery") ? " (or one of their recovery codes)" : "")
      : "The account's authenticator is a passkey, which the MCP server cannot use: ask the user for one of their " +
        "recovery codes (to stop using them up, they can add an authenticator app on the web dashboard, " +
        `${baseUrl(p.serverUrl)}/#/settings → Two-factor authentication)`;
    const minutes = Math.max(1, Math.round((p.expiresAt - this.now()) / 60_000));
    return {
      status: "mfa_required",
      methods: p.methods,
      message:
        `Two-factor authentication is required to sign in as "${p.username}". ${ask}, ` +
        `then call cpmesh_login again with the code; the password is not needed again for the next ${minutes} ` +
        `minute${minutes === 1 ? "" : "s"}. Never store or log the code.`,
    };
  }

  /** Sends the code; resolves null when the server no longer accepts the ticket. */
  private async verify(
    api: CpmeshApi,
    p: PendingSignIn,
    code: string,
  ): Promise<SignInResult | null> {
    const factor = codeMethod(code);
    if (!p.methods.includes(factor.method)) {
      throw new Error(
        factor.method === "totp"
          ? "This sign-in takes a recovery code, not a 6-digit code: the account had no authenticator app when it " +
              "started. Ask the user for one of their recovery codes, or, if they just added an authenticator app, " +
              "call cpmesh_login again with the password and the 6-digit code."
          : "That is not a 6-digit authenticator code, and the account has no recovery codes left: ask the user " +
              "for the current 6-digit code from their authenticator app.",
      );
    }
    try {
      const res = await api.verifyMfa(p.ticket, factor.method, factor.code);
      this.pending = null;
      return {
        status: "signed_in",
        auth: { access_token: res.access_token, refresh_token: res.refresh_token },
        recoveryCodesRemaining: res.recovery_codes_remaining,
      };
    } catch (e) {
      if (!(e instanceof ApiError)) throw e;
      // An expired or already used ticket is a 401 that asks to "sign in again"; a wrong code is a plain 401
      if (e.status === 401 && /sign in again/i.test(e.message)) {
        this.pending = null;
        return null;
      }
      if (e.code === "mfa_locked" || e.code === "account_suspended") this.pending = null;
      if (e.status === 401) {
        const retry =
          factor.method === "totp"
            ? "Ask the user for a new code from their authenticator app"
            : "Ask the user to check the recovery code (each one works once) or to use another";
        throw new Error(`The code was not accepted (${e.message}). ${retry}, then call cpmesh_login again with it.`);
      }
      throw readable(e);
    }
  }
}

function readable(e: unknown): unknown {
  if (!(e instanceof ApiError)) return e;
  if (e.code === "account_suspended") {
    return new Error(
      "This cpmesh account is suspended, so it cannot sign in. The user should contact the administrator of their cpmesh server.",
    );
  }
  if (e.code === "mfa_locked") {
    return new Error(`${e.message} After that, call cpmesh_login again with the password and a new code.`);
  }
  return e;
}
