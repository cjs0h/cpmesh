/**
 * The loopback redirect of a browser sign-in (RFC 8252 §7.3): a one-shot HTTP
 * listener on 127.0.0.1 that receives the authorization answer.
 *
 * Only a request that carries this sign-in's `state` counts. That one callback
 * ends the sign-in: it must name the expected issuer (RFC 9207) and carry a
 * code, otherwise the sign-in fails. Anything else is refused without ending
 * it, and the listener closes after the callback or when the time runs out.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

/** A sign-in that did not produce an authorization code. `error` is the OAuth error code, or our own. */
export class AuthorizationError extends Error {
  constructor(
    readonly error: string,
    message: string,
  ) {
    super(message);
  }
}

export interface Loopback {
  /** `http://127.0.0.1:{port}/callback` */
  redirectUri: string;
  /** The authorization code of the one valid callback. */
  code: Promise<string>;
  /** Stops waiting (the sign-in fails with `cancelled`). */
  close(): void;
}

export interface LoopbackOptions {
  state: string;
  /** The issuer the callback's `iss` must equal, exactly as discovered. */
  issuer: string;
  timeoutMs: number;
}

const PAGE_STYLE =
  "font-family: system-ui, sans-serif; max-width: 34rem; margin: 18vh auto; padding: 0 1.5rem; color: #111; line-height: 1.5";

function page(title: string, text: string): string {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · cpmesh</title></head>
<body style="${PAGE_STYLE}">
<h1 style="font-size: 1.25rem">${title}</h1>
<p>${text}</p>
</body>
</html>
`;
}

const SIGNED_IN = page("cpmesh is connected", "You can close this tab and go back to your AI agent.");
const DENIED = page("Sign-in cancelled", "Nothing was shared. You can close this tab.");
const FAILED = page("Sign-in failed", "Nothing was shared. Go back to your AI agent to start again.");
const NOT_OURS = page(
  "This sign-in link isn't valid",
  "It doesn't belong to the sign-in your AI agent is waiting for. Start again from the agent.",
);
const FINISHED = page("This sign-in is finished", "You can close this tab.");

function respond(res: ServerResponse, status: number, html: string): void {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    // The callback URL carries the code
    "Referrer-Policy": "no-referrer",
    Connection: "close",
  });
  res.end(html);
}

function failure(error: string, description: string | null): AuthorizationError {
  if (error === "access_denied") {
    return new AuthorizationError(error, "The user cancelled the sign-in in the browser.");
  }
  return new AuthorizationError(
    error,
    `The cpmesh server refused the sign-in (${error}${description ? `: ${description}` : ""}).`,
  );
}

export async function startLoopback({ state, issuer, timeoutMs }: LoopbackOptions): Promise<Loopback> {
  let resolveCode!: (code: string) => void;
  let rejectCode!: (error: AuthorizationError) => void;
  const code = new Promise<string>((resolve, reject) => {
    resolveCode = resolve;
    rejectCode = reject;
  });
  // Whoever waits for the code sees the failure; nobody waiting is not an error
  code.catch(() => undefined);

  let finished = false;
  let port = 0;
  let timer: NodeJS.Timeout | undefined;
  const server = createServer((req, res) => {
    try {
      handle(req, res);
    } catch {
      if (!res.headersSent) respond(res, 400, NOT_OURS);
    }
  });

  const finish = (outcome: { code: string } | { error: AuthorizationError }) => {
    if (finished) return;
    finished = true;
    clearTimeout(timer);
    server.close();
    server.closeIdleConnections?.();
    if ("code" in outcome) resolveCode(outcome.code);
    else rejectCode(outcome.error);
  };

  function handle(req: IncomingMessage, res: ServerResponse): void {
    if (finished) return respond(res, 404, FINISHED);
    if (req.method !== "GET") return respond(res, 405, NOT_OURS);
    // Only the browser's own request to this address (no DNS-rebound names)
    if (req.headers.host !== `127.0.0.1:${port}`) return respond(res, 400, NOT_OURS);
    const url = new URL(req.url ?? "/", `http://127.0.0.1:${port}`);
    if (url.pathname !== "/callback") return respond(res, 404, NOT_OURS);
    const params = url.searchParams;
    const single = (name: string) => {
      const values = params.getAll(name);
      return values.length === 1 ? values[0] : undefined;
    };
    if (single("state") !== state) return respond(res, 400, NOT_OURS);

    // The one callback of this sign-in
    if (single("iss") !== issuer) {
      respond(res, 400, FAILED);
      return finish({
        error: new AuthorizationError(
          "issuer_mismatch",
          `The sign-in answer did not come from ${issuer} (iss ${JSON.stringify(params.get("iss"))}), so it was refused.`,
        ),
      });
    }
    const error = params.get("error");
    if (error) {
      respond(res, 200, error === "access_denied" ? DENIED : FAILED);
      return finish({ error: failure(error, params.get("error_description")) });
    }
    const received = single("code");
    if (!received) {
      respond(res, 400, FAILED);
      return finish({ error: new AuthorizationError("invalid_request", "The sign-in answer had no authorization code.") });
    }
    respond(res, 200, SIGNED_IN);
    finish({ code: received });
  }

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  port = (server.address() as AddressInfo).port;
  timer = setTimeout(() => {
    const minutes = Math.round(timeoutMs / 60_000);
    finish({
      error: new AuthorizationError(
        "timeout",
        `Nobody approved the sign-in in the browser within ${minutes >= 1 ? `${minutes} minute${minutes === 1 ? "" : "s"}` : "the time allowed"}.`,
      ),
    });
  }, timeoutMs);
  timer.unref();
  return {
    redirectUri: `http://127.0.0.1:${port}/callback`,
    code,
    close: () => finish({ error: new AuthorizationError("cancelled", "The sign-in was cancelled.") }),
  };
}
