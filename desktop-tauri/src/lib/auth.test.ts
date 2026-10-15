import { describe, expect, it } from 'vitest';

import type { MfaPrompt } from './api.js';
import {
	APP_CALLBACK_URL,
	browserSignInUrl,
	codeChallenge,
	codeMethods,
	createCodeVerifier,
	keepCodeDigits,
	mfaErrorOf,
	mfaView,
	normalizeMfaCode,
	normalizeServerUrl,
	recoveryCodesLeftText,
	socialLoginUrl,
} from './auth.js';

function prompt(overrides: Partial<MfaPrompt> = {}): MfaPrompt {
	return {
		stage: 'verify',
		methods: ['totp', 'webauthn', 'recovery'],
		email_code_required: false,
		email_hint: null,
		passkeys_available: true,
		message: 'Two-factor authentication is required.',
		...overrides,
	};
}

describe('server URL', () => {
	it.each([
		['https://cpmesh.example', 'https://cpmesh.example'],
		['  https://cpmesh.example/  ', 'https://cpmesh.example'],
		['https://cpmesh.example///', 'https://cpmesh.example'],
		['http://localhost:8080/sub/', 'http://localhost:8080/sub'],
	])('normalizes %j', (input, expected) => {
		expect(normalizeServerUrl(input)).toBe(expected);
	});
});

describe('PKCE', () => {
	it('creates long random verifiers from unreserved characters', () => {
		const a = createCodeVerifier();
		const b = createCodeVerifier();
		expect(a).toMatch(/^[A-Za-z0-9\-._~]{64}$/);
		expect(b).toMatch(/^[A-Za-z0-9\-._~]{64}$/);
		expect(a).not.toBe(b);
	});

	it('derives the S256 challenge (RFC 7636 example)', async () => {
		await expect(codeChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).resolves.toBe(
			'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
		);
	});

	it('returns to the app through its deep link', () => {
		expect(socialLoginUrl('https://s', 'abc')).toBe(
			'https://s/api/auth/social/login?client_redirect=cpmesh%3A%2F%2Fauth%2Fcallback&code_challenge=abc&code_challenge_method=S256',
		);
		expect(browserSignInUrl('https://s', 'abc')).toBe(
			'https://s/#/login?client_redirect=cpmesh%3A%2F%2Fauth%2Fcallback&code_challenge=abc',
		);
		expect(APP_CALLBACK_URL).toBe('cpmesh://auth/callback');
	});
});

describe('second factor', () => {
	it('asks for a code when the account has an authenticator app or recovery codes', () => {
		expect(mfaView(prompt())).toBe('code');
		expect(codeMethods(prompt())).toEqual(['totp', 'recovery']);

		const totpOnly = prompt({ methods: ['totp'] });
		expect(mfaView(totpOnly)).toBe('code');
		expect(codeMethods(totpOnly)).toEqual(['totp']);

		// A passkey plus recovery codes: recovery codes work in the app
		const recoveryOnly = prompt({ methods: ['recovery', 'webauthn'] });
		expect(mfaView(recoveryOnly)).toBe('code');
		expect(codeMethods(recoveryOnly)).toEqual(['recovery']);
	});

	it('sends passkey-only accounts to the browser', () => {
		expect(mfaView(prompt({ methods: ['webauthn'] }))).toBe('passkey');
		expect(mfaView(prompt({ methods: [] }))).toBe('passkey');
		expect(codeMethods(prompt({ methods: ['webauthn'] }))).toEqual([]);
	});

	it('sends accounts without a second factor to set one up', () => {
		const enroll = prompt({ stage: 'enroll', methods: ['totp', 'webauthn'], email_code_required: true });
		expect(mfaView(enroll)).toBe('enroll');
		expect(codeMethods(enroll)).toEqual([]);
	});

	it('keeps up to six digits of a typed or pasted code', () => {
		expect(keepCodeDigits('123 456')).toBe('123456');
		expect(keepCodeDigits('12a3-4')).toBe('1234');
		expect(keepCodeDigits('1234567')).toBe('123456');
		expect(keepCodeDigits('')).toBe('');
	});

	it.each([
		['totp', '123456', '123456'],
		['totp', ' 123 456 ', '123456'],
		['totp', '123-456', '123456'],
		['totp', '12345', null],
		['totp', '1234567', null],
		['totp', '12345a', null],
		['recovery', 'abcd-efgh-ijkl-mnop', 'abcdefghijklmnop'],
		['recovery', 'ABCD EFGH IJKL MNOP', 'abcdefghijklmnop'],
		['recovery', 'abcd-efgh-ijkl-mno', null],
		// 0, 1, 8 and 9 are not base32
		['recovery', 'abcd-efgh-ijkl-mn01', null],
		['recovery', '', null],
	] as const)('normalizes %s code %j', (method, input, expected) => {
		expect(normalizeMfaCode(method, input)).toBe(expected);
	});

	it('reads the backend error, whatever shape it arrives in', () => {
		expect(mfaErrorOf({ message: 'Invalid authentication code', restart: false })).toEqual({
			message: 'Invalid authentication code',
			restart: false,
		});
		expect(mfaErrorOf({ message: 'Your sign-in expired. Sign in again.', restart: true })).toEqual({
			message: 'Your sign-in expired. Sign in again.',
			restart: true,
		});
		// Rejected before reaching the command (e.g. invalid arguments)
		expect(mfaErrorOf('invalid args `method`')).toEqual({ message: 'invalid args `method`', restart: false });
		expect(mfaErrorOf(new Error('IPC failed'))).toEqual({ message: 'IPC failed', restart: false });
		expect(mfaErrorOf(undefined)).toEqual({ message: 'undefined', restart: false });
	});

	it.each([
		[0, 'You have no recovery codes left.'],
		[1, 'You have 1 recovery code left.'],
		[9, 'You have 9 recovery codes left.'],
	])('counts %i remaining recovery codes', (count, text) => {
		expect(recoveryCodesLeftText(count)).toBe(text);
	});
});
