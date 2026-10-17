/**
 * Where the user approves a sign-in: in a browser on this computer (loopback
 * redirect), or in any browser with a code (device authorization) when this
 * process can't reach one: over SSH, in a container, or without a display.
 */

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";

export type SignInMode = "browser" | "device";

export interface ModeChoice {
  mode: SignInMode;
  /** Why the device flow was chosen. */
  reason?: string;
}

export function detectSignInMode(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
  exists: (path: string) => boolean = existsSync,
): ModeChoice {
  if (env.SSH_CONNECTION || env.SSH_TTY) {
    return { mode: "device", reason: "this MCP server runs over SSH" };
  }
  if (exists("/.dockerenv") || exists("/run/.containerenv") || env.container || env.CODESPACES || env.REMOTE_CONTAINERS) {
    return { mode: "device", reason: "this MCP server runs in a container" };
  }
  if (platform === "linux" && !env.DISPLAY && !env.WAYLAND_DISPLAY) {
    return { mode: "device", reason: "this computer has no display" };
  }
  return { mode: "browser" };
}

type Spawn = typeof spawn;

/**
 * Opens `url` in the default browser. Resolves false when no browser could be
 * started; an opener still running after a moment has handed over to the browser.
 */
export function openBrowser(url: string, platform: NodeJS.Platform = process.platform, spawnImpl: Spawn = spawn): Promise<boolean> {
  const [command, args]: [string, string[]] =
    platform === "darwin" ? ["open", [url]]
      // No shell: `start` would need the URL's & escaped
      : platform === "win32" ? ["rundll32.exe", ["url.dll,FileProtocolHandler", url]]
        : ["xdg-open", [url]];
  return new Promise((resolve) => {
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    const settle = (opened: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(opened);
    };
    let child: ReturnType<Spawn>;
    try {
      // stdout is the MCP channel: the opener must never write to it
      child = spawnImpl(command, args, { stdio: "ignore", detached: true, windowsHide: true });
    } catch {
      settle(false);
      return;
    }
    child.once("error", () => settle(false));
    // rundll32 reports nothing useful in its exit code
    if (platform === "win32") child.once("spawn", () => settle(true));
    child.once("exit", (code) => settle(code === 0));
    timer = setTimeout(() => settle(true), 2_000);
    timer.unref();
    child.unref();
  });
}
