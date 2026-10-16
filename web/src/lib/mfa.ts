// Two-factor authentication: the `/api/mfa/*` endpoints and the browser side of
// passkeys (WebAuthn).
//
// The endpoints serve two callers: a sign-in waiting for its second factor, which
// authenticates with the sign-in ticket (`mfa_token`) from the login response, and a
// signed-in user, who uses the session. Helpers take an `MfaTransport` for that reason.

import { api, apiWithToken, ApiError, requestReauth } from './api';
import { appCallbackUrl, getAccessToken, setTokens, type AppSignIn } from './auth';

export type MfaMethod = 'totp' | 'webauthn' | 'recovery';
export type MfaStage = 'verify' | 'enroll';

/** The second step of a sign-in (the `mfa_required` answer to the first one). */
export interface MfaChallenge {
  /** Sign-in ticket: valid for 10 minutes, single use. */
  mfa_token: string;
  /** `verify`: confirm a factor the account has; `enroll`: set one up. */
  stage: MfaStage;
  /** verify: the factors the account has; enroll: the ones it can set up. */
  methods: MfaMethod[];
  /** Enroll after a password: confirm a code emailed to the account first. */
  email_code_required: boolean;
  email_hint: string | null;
  passkeys_available: boolean;
}

export interface Passkey {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
  /** Synced by a passkey provider (iCloud Keychain, Google Password Manager, …). */
  backup_eligible: boolean;
}

/** `GET /api/mfa`. Session fields are null for a sign-in ticket, `stage` is null for a session. */
export interface MfaStatus {
  required: boolean;
  enabled: boolean;
  totp: boolean;
  passkeys: Passkey[];
  recovery_codes_remaining: number;
  passkeys_available: boolean;
  session_verified: boolean | null;
  recent_auth: boolean | null;
  has_password: boolean;
  stage: MfaStage | null;
  email_code_required: boolean;
}

export interface SessionTokens {
  access_token: string;
  refresh_token: string;
}

/** A factor was set up. `recovery_codes` comes with the first one: show them once. */
export interface EnrollResult extends SessionTokens {
  recovery_codes?: string[];
}

export interface VerifyResult extends SessionTokens {
  recovery_codes_remaining?: number;
}

export interface TotpSetup {
  /** Base32, for typing into an authenticator app. */
  secret: string;
  otpauth_uri: string;
  /** QR code of `otpauth_uri` as SVG markup. */
  qr_svg: string | null;
}

export type VerifyBody =
  | { method: 'totp' | 'recovery'; code: string }
  | { method: 'webauthn'; challenge_token: string; credential: AssertionJSON }
  | { method: 'password'; password: string };

/** Sends a request to the two-factor endpoints, as a sign-in in progress or as the session. */
export type MfaTransport = <T>(path: string, init?: RequestInit) => Promise<T>;

/** Authenticates with the sign-in ticket, read per request (verifying the emailed code replaces it). */
export function ticketTransport(ticket: () => string): MfaTransport {
  return (path, init) => apiWithToken(path, ticket(), init);
}

/**
 * Authenticates with the session. Wrong codes and passwords are answered with 401 too
 * (marked `invalid_code` / `invalid_password`), so unlike `api()` this sends a request
 * again only when the session had expired: a repeated wrong code would count twice
 * towards the lockout, and passkey challenges work once. `reauth_required` asks the
 * user to confirm it's them, then retries.
 */
export const sessionTransport: MfaTransport = (path, init) => sendWithSession(path, init, {});

async function sendWithSession<T>(path: string, init: RequestInit | undefined, tried: { refresh?: boolean; reauth?: boolean }): Promise<T> {
  const token = getAccessToken();
  try {
    return await apiWithToken<T>(path, token, init);
  } catch (err) {
    if (!(err instanceof ApiError)) throw err;
    if (err.code === 'reauth_required' && !tried.reauth) {
      if (!(await requestReauth())) throw err;
      return sendWithSession<T>(path, init, { ...tried, reauth: true });
    }
    const wrongCredentials = err.code === 'invalid_code' || err.code === 'invalid_password';
    if (err.status === 401 && !wrongCredentials && !tried.refresh) {
      // `api()` refreshes an expired session, or signs out when it can't be
      await api('/api/mfa');
      if (getAccessToken() !== token) return sendWithSession<T>(path, init, { ...tried, refresh: true });
    }
    throw err;
  }
}

function post(body?: unknown): RequestInit {
  return body === undefined ? { method: 'POST' } : { method: 'POST', body: JSON.stringify(body) };
}

export function getMfaStatus(send: MfaTransport) {
  return send<MfaStatus>('/api/mfa');
}

export function sendEmailCode(send: MfaTransport) {
  return send<{ sent: boolean; email_hint: string | null }>('/api/mfa/email-code', post());
}

/** Resolves to a new sign-in ticket that replaces the current one. */
export async function verifyEmailCode(send: MfaTransport, code: string): Promise<string> {
  const { mfa_token } = await send<{ mfa_token: string }>('/api/mfa/email-code/verify', post({ code }));
  return mfa_token;
}

export function startTotpSetup(send: MfaTransport) {
  return send<TotpSetup>('/api/mfa/totp/setup', post());
}

export function enableTotp(send: MfaTransport, code: string) {
  return send<EnrollResult>('/api/mfa/totp/enable', post({ code }));
}

export function verifyFactor(send: MfaTransport, body: VerifyBody) {
  return send<VerifyResult>('/api/mfa/verify', post(body));
}

/** Creates a passkey on this device and registers it under `name`. */
export async function addPasskey(send: MfaTransport, name: string): Promise<EnrollResult & { passkey: Passkey }> {
  const { options, challenge_token } = await send<{ options: CreationOptionsJSON; challenge_token: string }>(
    '/api/mfa/passkeys/options',
    post(),
  );
  const credential = await createPasskey(options);
  return send('/api/mfa/passkeys', post({ challenge_token, name, credential }));
}

/** Confirms the second factor with one of the account's passkeys. */
export async function verifyWithPasskey(send: MfaTransport): Promise<VerifyResult> {
  const { options, challenge_token } = await send<{ options: RequestOptionsJSON; challenge_token: string }>(
    '/api/mfa/verify/options',
    post(),
  );
  const credential = await getPasskeyAssertion(options);
  return verifyFactor(send, { method: 'webauthn', challenge_token, credential });
}

// Managing factors needs the session (and a recent confirmation, which `api()` asks for)

export function renamePasskey(id: string, name: string) {
  return api<{ id: string; name: string }>(`/api/mfa/passkeys/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify({ name }),
  });
}

export function removePasskey(id: string) {
  return api<{ message: string }>(`/api/mfa/passkeys/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export function removeTotp() {
  return api<{ message: string }>('/api/mfa/totp', { method: 'DELETE' });
}

/** Replaces the recovery codes; the old ones stop working. */
export async function regenerateRecoveryCodes(): Promise<string[]> {
  const { recovery_codes } = await api<{ recovery_codes: string[] }>('/api/mfa/recovery-codes', post());
  return recovery_codes;
}

const METHODS: readonly MfaMethod[] = ['totp', 'webauthn', 'recovery'];

/** The second step from an `mfa_required` error body, or null when it is not one. */
export function challengeFromBody(data: Record<string, unknown>): MfaChallenge | null {
  if (data.code !== 'mfa_required' || typeof data.mfa_token !== 'string' || !data.mfa_token) return null;
  const methods = Array.isArray(data.methods) ? data.methods : [];
  return {
    mfa_token: data.mfa_token,
    stage: data.stage === 'enroll' ? 'enroll' : 'verify',
    methods: METHODS.filter((m) => methods.includes(m)),
    email_code_required: data.email_code_required === true,
    email_hint: typeof data.email_hint === 'string' ? data.email_hint : null,
    passkeys_available: data.passkeys_available === true,
  };
}

/** The factors an account can confirm with, from its status. */
export function verifyMethods(status: MfaStatus): MfaMethod[] {
  const methods: MfaMethod[] = [];
  if (status.totp) methods.push('totp');
  if (status.passkeys_available && status.passkeys.length > 0) methods.push('webauthn');
  if (status.recovery_codes_remaining > 0) methods.push('recovery');
  return methods;
}

/** The second step of a sign-in that only has its ticket (SSO), from `GET /api/mfa`. */
export function challengeFromStatus(ticket: string, status: MfaStatus): MfaChallenge {
  const stage: MfaStage = status.stage ?? (status.enabled ? 'verify' : 'enroll');
  const methods: MfaMethod[] =
    stage === 'verify' ? verifyMethods(status) : status.passkeys_available ? ['totp', 'webauthn'] : ['totp'];
  return {
    mfa_token: ticket,
    stage,
    methods,
    email_code_required: status.email_code_required,
    email_hint: null,
    passkeys_available: status.passkeys_available,
  };
}

/** Page heading for the second step of a sign-in. */
export function secondStepHeading(stage: MfaStage): { title: string; subtitle: string } {
  return stage === 'verify'
    ? { title: 'Two-factor authentication', subtitle: "Confirm it's you to finish signing in." }
    : { title: 'Set up two-factor authentication', subtitle: 'Your account needs a second step at sign-in. It only takes a minute.' };
}

/**
 * Finishes a sign-in with its new tokens. When the desktop app asked for the sign-in
 * they are exchanged for a one-time code, and the returned `cpmesh://` URL hands it to
 * the app (this browser stays signed out). Otherwise the session is stored; returns null.
 */
export async function completeSignIn(tokens: SessionTokens, app: AppSignIn | null): Promise<string | null> {
  if (!app) {
    setTokens(tokens.access_token, tokens.refresh_token);
    return null;
  }
  const { code } = await apiWithToken<{ code: string }>(
    '/api/auth/native-code',
    tokens.access_token,
    post({ code_challenge: app.codeChallenge }),
  );
  return appCallbackUrl(app, code);
}

/** Whether `err` means the user backed out: closed the passkey prompt or the "confirm it's you" dialog. */
export function isCancellation(err: unknown): boolean {
  return (err instanceof PasskeyError && err.cancelled) || (err instanceof ApiError && err.code === 'reauth_required');
}

/** A sentence-case message for showing `err` to the user. */
export function errorMessage(err: unknown, fallback = 'Something went wrong. Try again.'): string {
  const message = err instanceof Error && err.message ? err.message : fallback;
  return message.charAt(0).toUpperCase() + message.slice(1);
}

/** Digits of a 6-digit code as typed or pasted ("123 456" → "123456"). */
export function normalizeOtp(value: string): string {
  return value.replace(/\D/g, '').slice(0, 6);
}

/** The QR code as an image URL: rendered as an image, the SVG markup can't run scripts. */
export function svgDataUrl(svg: string): string {
  let binary = '';
  for (const byte of new TextEncoder().encode(svg)) binary += String.fromCharCode(byte);
  return `data:image/svg+xml;base64,${btoa(binary)}`;
}

/** Plain-text file with the recovery codes, for the user to keep. */
export function recoveryCodesText(codes: string[], account = ''): string {
  return [
    `cpmesh recovery codes${account ? ` for ${account}` : ''}`,
    '',
    'Each code works once, when you cannot use your authenticator app or passkey.',
    'Keep them somewhere safe, such as a password manager.',
    '',
    ...codes,
    '',
  ].join('\n');
}

/** Saves `text` as a download named `filename`. */
export function downloadText(filename: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** A starting name for a passkey made on this device. */
export function defaultPasskeyName(userAgent: string = globalThis.navigator?.userAgent ?? ''): string {
  const platforms: [RegExp, string][] = [
    [/iPhone/, 'iPhone'],
    [/iPad/, 'iPad'],
    [/Android/, 'Android'],
    [/CrOS/, 'Chromebook'],
    [/Macintosh|Mac OS X/, 'Mac'],
    [/Windows/, 'Windows'],
    [/Linux/, 'Linux'],
  ];
  return platforms.find(([pattern]) => pattern.test(userAgent))?.[1] ?? 'Passkey';
}

// === Passkeys (WebAuthn) ===
//
// The server sends the ceremony options as JSON with base64url strings for binary
// fields; the browser API wants ArrayBuffers, and its results go back as base64url.

interface CredentialDescriptorJSON {
  type: 'public-key';
  id: string;
  transports?: string[];
}

/** `PublicKeyCredentialCreationOptions` with base64url binary fields. */
export interface CreationOptionsJSON {
  challenge: string;
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  timeout?: number;
  attestation?: AttestationConveyancePreference;
  excludeCredentials?: CredentialDescriptorJSON[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
}

/** `PublicKeyCredentialRequestOptions` with base64url binary fields. */
export interface RequestOptionsJSON {
  challenge: string;
  rpId?: string;
  allowCredentials?: CredentialDescriptorJSON[];
  userVerification?: UserVerificationRequirement;
  timeout?: number;
}

export interface RegistrationJSON {
  id: string;
  rawId: string;
  type: string;
  response: { clientDataJSON: string; attestationObject: string; transports: string[] };
}

export interface AssertionJSON {
  id: string;
  rawId: string;
  type: string;
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle: string | null };
}

/** A passkey prompt that did not finish. `cancelled`: dismissed by the user or timed out. */
export class PasskeyError extends Error {
  readonly cancelled: boolean;

  constructor(message: string, cancelled = false) {
    super(message);
    this.name = 'PasskeyError';
    this.cancelled = cancelled;
  }
}

export function base64urlToBuffer(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/** base64url without padding. */
export function bufferToBase64url(data: ArrayBuffer | ArrayBufferView): string {
  const bytes = ArrayBuffer.isView(data) ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength) : new Uint8Array(data);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Whether this browser can create and use passkeys. */
export function passkeysSupported(): boolean {
  return (
    typeof globalThis.PublicKeyCredential === 'function' &&
    typeof globalThis.navigator?.credentials?.create === 'function' &&
    typeof globalThis.navigator?.credentials?.get === 'function'
  );
}

function descriptors(list: CredentialDescriptorJSON[] | undefined): PublicKeyCredentialDescriptor[] | undefined {
  return list?.map((d) => ({
    type: d.type,
    id: base64urlToBuffer(d.id),
    ...(d.transports ? { transports: d.transports as AuthenticatorTransport[] } : {}),
  }));
}

export function toCreationOptions(json: CreationOptionsJSON): PublicKeyCredentialCreationOptions {
  return {
    ...json,
    challenge: base64urlToBuffer(json.challenge),
    user: { ...json.user, id: base64urlToBuffer(json.user.id) },
    excludeCredentials: descriptors(json.excludeCredentials),
  };
}

export function toRequestOptions(json: RequestOptionsJSON): PublicKeyCredentialRequestOptions {
  return {
    ...json,
    challenge: base64urlToBuffer(json.challenge),
    allowCredentials: descriptors(json.allowCredentials),
  };
}

function passkeyError(err: unknown): PasskeyError {
  if (err instanceof PasskeyError) return err;
  switch ((err as { name?: string } | null)?.name) {
    case 'NotAllowedError':
    case 'AbortError':
      return new PasskeyError('The passkey prompt was closed or timed out.', true);
    case 'InvalidStateError':
      return new PasskeyError('This device already has a passkey for your account.');
    case 'SecurityError':
      return new PasskeyError("Passkeys don't work on this address. Open the dashboard at its usual address and try again.");
    case 'NotSupportedError':
      return new PasskeyError("This device doesn't support the passkey types this server accepts.");
    default:
      return new PasskeyError(err instanceof Error && err.message ? err.message : 'The passkey request failed.');
  }
}

async function ceremony(run: () => Promise<Credential | null>): Promise<PublicKeyCredential> {
  if (!passkeysSupported()) throw new PasskeyError("This browser doesn't support passkeys.");
  let credential: Credential | null;
  try {
    credential = await run();
  } catch (err) {
    throw passkeyError(err);
  }
  if (!credential) throw new PasskeyError('The passkey prompt was closed or timed out.', true);
  return credential as PublicKeyCredential;
}

/** Runs `navigator.credentials.create()` for the server's options and serializes the new credential. */
export async function createPasskey(options: CreationOptionsJSON): Promise<RegistrationJSON> {
  const credential = await ceremony(() => navigator.credentials.create({ publicKey: toCreationOptions(options) }));
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      attestationObject: bufferToBase64url(response.attestationObject),
      transports: response.getTransports?.() ?? [],
    },
  };
}

/** Runs `navigator.credentials.get()` for the server's options and serializes the assertion. */
export async function getPasskeyAssertion(options: RequestOptionsJSON): Promise<AssertionJSON> {
  const credential = await ceremony(() => navigator.credentials.get({ publicKey: toRequestOptions(options) }));
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      authenticatorData: bufferToBase64url(response.authenticatorData),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
    },
  };
}
