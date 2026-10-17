// AI agents signing in with OAuth: the consent pages (`#/authorize` when the agent
// can open a browser on this computer, `#/activate` for a device code) and the
// "Connected agents" list.
//
// Anyone can craft a consent link, and the server checks every answer again. The
// checks here only keep the pages from offering what the server would refuse.

import { api, ApiError, requestReauth } from './api';

/** Scopes an agent can ask for, in the server's order. */
export const SCOPES = ['clipboard:read', 'clipboard:write', 'clipboard:delete', 'devices:manage'] as const;
export type Scope = (typeof SCOPES)[number];

export interface ScopeInfo {
  /** Consent toggle. */
  label: string;
  /** Badge in the list of connected agents. */
  short: string;
  description: string;
  icon: string;
}

export const SCOPE_INFO: Record<Scope, ScopeInfo> = {
  'clipboard:read': {
    label: 'Read the clipboard',
    short: 'Read',
    description: 'See your clipboard history and new entries as they arrive.',
    icon: 'eye',
  },
  'clipboard:write': {
    label: 'Send to the clipboard',
    short: 'Send',
    description: 'Add entries that show up on your devices.',
    icon: 'send',
  },
  'clipboard:delete': {
    label: 'Delete clipboard entries',
    short: 'Delete entries',
    description: 'Remove single entries from your history.',
    icon: 'trash',
  },
  'devices:manage': {
    label: 'Manage devices',
    short: 'Manage devices',
    description: 'Remove other devices from your account.',
    icon: 'monitor',
  },
};

/** A scope as the approval page and the agent name it: "Read the clipboard (clipboard:read)". */
export function scopeLabel(scope: Scope): string {
  return `${SCOPE_INFO[scope].label} (${scope})`;
}

/** On by default when requested; the user opts in to the others. */
const DEFAULT_SCOPES: readonly Scope[] = ['clipboard:read', 'clipboard:write'];

/** Registered clients and how they are shown. */
const CLIENT_NAMES = new Map([['cpmesh-mcp', 'cpmesh MCP']]);

export function clientName(clientId: string): string | null {
  return CLIENT_NAMES.get(clientId) ?? null;
}

function isScope(name: string): name is Scope {
  return (SCOPES as readonly string[]).includes(name);
}

/** Scopes from a scope string (names separated by spaces), in order; null when one isn't known. */
export function parseScopes(value: string | null | undefined): Scope[] | null {
  const names = (value ?? '').split(/[\t\n\f\r ]+/).filter(Boolean);
  if (!names.every(isScope)) return null;
  return SCOPES.filter((scope) => names.includes(scope));
}

/** The known scopes in a list from the server, in order. */
export function knownScopes(names: readonly string[]): Scope[] {
  return SCOPES.filter((scope) => names.includes(scope));
}

/** What the consent toggles start with: read and write, when the agent asked for them. */
export function defaultScopes(requested: readonly Scope[]): Scope[] {
  return requested.filter((scope) => DEFAULT_SCOPES.includes(scope));
}

export function scopeString(scopes: readonly Scope[]): string {
  return SCOPES.filter((scope) => scopes.includes(scope)).join(' ');
}

// === Browser flow: authorization code + PKCE (`#/authorize`) ===

/** An authorization request as the server forwards it to `#/authorize`. */
export interface AuthorizeRequest {
  clientId: string;
  clientName: string;
  /** The agent's listener on this computer, e.g. `http://127.0.0.1:53682/callback`. */
  redirectUri: string;
  /** `redirectUri` for people: `127.0.0.1:53682`. */
  listener: string;
  state: string;
  codeChallenge: string;
  /** The scopes the agent asked for. */
  scopes: Scope[];
  /** The agent's name for itself, as it reported it; may be empty. */
  agentName: string;
}

export type ParsedAuthorizeRequest = { request: AuthorizeRequest; error?: undefined } | { request?: undefined; error: string };

const AUTHORIZE_PARAMS = [
  'client_id',
  'redirect_uri',
  'response_type',
  'state',
  'code_challenge',
  'code_challenge_method',
  'scope',
  'agent_name',
] as const;

const LOOPBACK_REDIRECT = /^http:\/\/(127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})\/callback$/;
const STATE = /^[\x20-\x7e]{1,512}$/;
const CODE_CHALLENGE = /^[A-Za-z0-9_-]{43,128}$/;
/** Characters an agent name may not contain: control characters, and ones that reorder or break text. */
const HIDDEN_CHARACTERS = /[\p{Cc}\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u;
const AGENT_NAME_MAX = 100;

/** `host:port` of a loopback redirect URI the server accepts; null for anything else. */
export function loopbackListener(uri: string): string | null {
  const match = LOOPBACK_REDIRECT.exec(uri);
  if (!match || Number(match[2]) > 65535) return null;
  return `${match[1]}:${match[2]}`;
}

/** An agent name as the server accepts it (trimmed), or null. */
export function agentNameFrom(value: string | null): string | null {
  const name = (value ?? '').trim();
  if ([...name].length > AGENT_NAME_MAX || HIDDEN_CHARACTERS.test(name)) return null;
  return name;
}

/** Reads the request from the `#/authorize` query, or says what is wrong with it. */
export function parseAuthorizeRequest(querystring: string | null | undefined): ParsedAuthorizeRequest {
  const params = new URLSearchParams(querystring ?? '');
  const repeated = AUTHORIZE_PARAMS.find((name) => params.getAll(name).length > 1);
  if (repeated) return { error: `${repeated} is repeated.` };
  // Empty values count as absent
  const get = (name: (typeof AUTHORIZE_PARAMS)[number]) => params.get(name) || null;

  const clientId = get('client_id') ?? '';
  const name = clientName(clientId);
  if (!name) return { error: "It is for an app this server doesn't know." };
  const redirectUri = get('redirect_uri') ?? '';
  const listener = loopbackListener(redirectUri);
  if (!listener) return { error: "It doesn't return to an agent on this computer." };
  if (get('response_type') !== 'code') return { error: "It isn't a sign-in request." };
  const state = get('state');
  if (!state || !STATE.test(state)) return { error: 'Its state is missing or invalid.' };
  const codeChallenge = get('code_challenge');
  if (get('code_challenge_method') !== 'S256' || !codeChallenge || !CODE_CHALLENGE.test(codeChallenge)) {
    return { error: 'Its code challenge is missing or invalid.' };
  }
  const scopes = parseScopes(get('scope'));
  if (!scopes) return { error: "It asks for permissions this server doesn't know." };
  const agentName = agentNameFrom(get('agent_name'));
  if (agentName === null) return { error: "The agent's name is too long or has hidden characters." };

  return {
    request: {
      clientId,
      clientName: name,
      redirectUri,
      listener,
      state,
      codeChallenge,
      // No scope: the agent asks for everything, and the user chooses
      scopes: scopes.length ? scopes : [...SCOPES],
      agentName,
    },
  };
}

export type Decision = 'approve' | 'deny';

function post(body: unknown): RequestInit {
  return { method: 'POST', body: JSON.stringify(body) };
}

/**
 * Runs a consent request, confirming it's the user when the server asks. `api()`
 * handles `reauth_required` with the "confirm it's you" dialog; a session that wasn't
 * confirmed with a second factor (`mfa_required`) gets the same dialog. Then it
 * retries once.
 */
export async function withStepUp<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (err) {
    if (err instanceof ApiError && err.code === 'mfa_required' && (await requestReauth())) return run();
    throw err;
  }
}

/** Whether `err` is a "confirm it's you" that didn't happen (the user closed the dialog). */
export function isStepUpRequired(err: unknown): boolean {
  return err instanceof ApiError && (err.code === 'reauth_required' || err.code === 'mfa_required');
}

/**
 * Approves (with the scopes the user chose) or denies an authorization request.
 * Resolves to where the browser goes next: the agent's listener, with a code or the
 * denial.
 */
export async function decideAuthorization(request: AuthorizeRequest, decision: Decision, scopes: readonly Scope[] = []): Promise<string> {
  const target = { client_id: request.clientId, redirect_uri: request.redirectUri, state: request.state };
  const body =
    decision === 'approve'
      ? {
          ...target,
          code_challenge: request.codeChallenge,
          code_challenge_method: 'S256',
          scope: scopeString(scopes),
          agent_name: request.agentName,
          decision,
        }
      : { ...target, decision };
  const { redirect_to } = await withStepUp(() => api<{ redirect_to?: unknown }>('/api/oauth/authorize', post(body)));
  // Only ever leave for the listener the user was shown
  if (typeof redirect_to !== 'string' || !redirect_to.startsWith(`${request.redirectUri}?`)) {
    throw new Error("The server's answer doesn't lead back to your agent. Start again from your agent.");
  }
  return redirect_to;
}

// === Device authorization grant (`#/activate`) ===

/** The 20 consonants user codes are made of. */
export const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';
const USER_CODE_LENGTH = 8;

/**
 * A user code as typed ("bcdf ghjk"), as the server reads it: ASCII letters
 * upper-cased, dashes and spaces dropped ("BCDFGHJK"). Null unless eight letters of
 * the alphabet remain.
 */
export function normalizeUserCode(input: string): string | null {
  if (input.length > 64) return null;
  const code = input.replace(/[-\s]/g, '').replace(/[a-z]/g, (letter) => letter.toUpperCase());
  if (code.length !== USER_CODE_LENGTH || ![...code].every((c) => USER_CODE_ALPHABET.includes(c))) return null;
  return code;
}

/** A normalized user code as people see it: "BCDF-GHJK". */
export function formatUserCode(code: string): string {
  return `${code.slice(0, USER_CODE_LENGTH / 2)}-${code.slice(USER_CODE_LENGTH / 2)}`;
}

/** `GET /api/oauth/device`: a pending, unexpired request. */
export interface DeviceRequest {
  user_code: string;
  client_id: string;
  client_name: string | null;
  /** As reported by the agent; may be empty. */
  agent_name: string;
  /** The scopes the agent asked for. */
  scopes: string[];
  requester_ip: string;
  user_agent: string | null;
  created_at: string;
  expires_at: string;
}

export function lookupDeviceRequest(userCode: string): Promise<DeviceRequest> {
  return api<DeviceRequest>(`/api/oauth/device?user_code=${encodeURIComponent(userCode)}`);
}

export function approveDeviceRequest(userCode: string, scopes: readonly Scope[]) {
  return withStepUp(() =>
    api<{ status: 'approved'; scope: string }>('/api/oauth/device/approve', post({ user_code: userCode, scope: scopeString(scopes) })),
  );
}

export function denyDeviceRequest(userCode: string) {
  return withStepUp(() => api<{ status: 'denied' }>('/api/oauth/device/deny', post({ user_code: userCode })));
}

// === Connected agents ===

export interface AgentGrant {
  id: string;
  client_id: string;
  client_name: string | null;
  /** As reported by the agent; may be empty. */
  agent_name: string;
  scopes: string[];
  /** Null until the agent registers its device. */
  device: { id: string; name: string | null; status: string } | null;
  created_at: string;
  last_used_at: string | null;
  /** `signed_out`: its sessions ended, but it wasn't revoked and its device stays paired. */
  status: 'active' | 'signed_out';
}

/** The user's agents, newest first. */
export function listAgentGrants(): Promise<AgentGrant[]> {
  return api<AgentGrant[]>('/api/oauth/grants');
}

/** Signs the agent out for good and removes its device. */
export function revokeAgentGrant(id: string): Promise<void> {
  return api<void>(`/api/oauth/grants/${encodeURIComponent(id)}`, { method: 'DELETE' });
}
