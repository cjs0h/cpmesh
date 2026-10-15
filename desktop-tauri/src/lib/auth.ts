// Sign-in helpers: PKCE for handing a browser sign-in to the app, and the second-factor step.

import type { MfaCodeMethod, MfaLoginError, MfaPrompt } from './api';

/** Where the browser sends a finished sign-in back to the app (deep link). */
export const APP_CALLBACK_URL = 'cpmesh://auth/callback';

/** The server URL without surrounding spaces or trailing slashes. */
export function normalizeServerUrl(url: string): string {
	return url.trim().replace(/\/+$/, '');
}

// RFC 7636 unreserved characters
const VERIFIER_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

/** A random PKCE code verifier: the secret that redeems the code the browser sends back. */
export function createCodeVerifier(): string {
	const bytes = new Uint8Array(64);
	crypto.getRandomValues(bytes);
	return Array.from(bytes, (b) => VERIFIER_CHARSET[b % VERIFIER_CHARSET.length]).join('');
}

/** The S256 challenge for `verifier`: base64url(SHA-256(verifier)) without padding. */
export async function codeChallenge(verifier: string): Promise<string> {
	const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
	const base64 = btoa(String.fromCharCode(...new Uint8Array(hash)));
	return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Single sign-on with the server's identity provider. */
export function socialLoginUrl(baseUrl: string, challenge: string): string {
	return `${baseUrl}/api/auth/social/login?client_redirect=${encodeURIComponent(APP_CALLBACK_URL)}&code_challenge=${encodeURIComponent(challenge)}&code_challenge_method=S256`;
}

/**
 * Sign-in on the web dashboard, which also handles passkeys and setting up two-factor
 * authentication, then hands the session to the app.
 */
export function browserSignInUrl(baseUrl: string, challenge: string): string {
	return `${baseUrl}/#/login?client_redirect=${encodeURIComponent(APP_CALLBACK_URL)}&code_challenge=${encodeURIComponent(challenge)}`;
}

/**
 * How the sign-in continues after the password: a code typed into the app, a passkey
 * (in the browser), or setting up two-factor authentication on the web dashboard.
 */
export type MfaView = 'code' | 'passkey' | 'enroll';

/** The codes the app can take for `prompt`, preferred first. */
export function codeMethods(prompt: MfaPrompt): MfaCodeMethod[] {
	if (prompt.stage !== 'verify') return [];
	return (['totp', 'recovery'] as const).filter((method) => prompt.methods.includes(method));
}

export function mfaView(prompt: MfaPrompt): MfaView {
	if (prompt.stage !== 'verify') return 'enroll';
	return codeMethods(prompt).length > 0 ? 'code' : 'passkey';
}

/** The digits of a typed or pasted authenticator code, at most six. */
export function keepCodeDigits(input: string): string {
	return input.replace(/\D/g, '').slice(0, 6);
}

/**
 * The code to send, or null when `input` cannot be one. The server counts malformed
 * codes as failed attempts, so they are caught here.
 */
export function normalizeMfaCode(method: MfaCodeMethod, input: string): string | null {
	const compact = input.replace(/[\s-]/g, '');
	if (method === 'totp') return /^\d{6}$/.test(compact) ? compact : null;
	// Recovery codes: 16 base32 characters, shown as abcd-efgh-ijkl-mnop
	const code = compact.toLowerCase();
	return /^[a-z2-7]{16}$/.test(code) ? code : null;
}

/** The error `completeMfaLogin` failed with; unexpected ones leave the sign-in open. */
export function mfaErrorOf(e: unknown): MfaLoginError {
	if (typeof e === 'object' && e !== null && typeof (e as MfaLoginError).message === 'string') {
		return { message: (e as MfaLoginError).message, restart: (e as MfaLoginError).restart === true };
	}
	return { message: String(e), restart: false };
}

export function recoveryCodesLeftText(count: number): string {
	if (count === 0) return 'You have no recovery codes left.';
	return `You have ${count} recovery ${count === 1 ? 'code' : 'codes'} left.`;
}
