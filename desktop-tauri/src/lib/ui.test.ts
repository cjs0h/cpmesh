import { afterEach, describe, expect, it, vi } from 'vitest';
import {
	contentKind,
	dayLabel,
	deviceIcon,
	errorMessage,
	fingerprintGroups,
	forgetServerUrl,
	formatRelative,
	formatSize,
	getLastServerUrl,
	rememberServerUrl,
	serverHost,
	shortcutKeys,
	toServerUrl,
} from './ui';

describe('toServerUrl', () => {
	it('assumes https and drops trailing slashes', () => {
		expect(toServerUrl('  cpmesh.example.com/ ')).toBe('https://cpmesh.example.com');
		expect(toServerUrl('cpmesh.example.com:8443')).toBe('https://cpmesh.example.com:8443');
	});

	it('keeps an explicit http or https scheme', () => {
		expect(toServerUrl('http://localhost:3000')).toBe('http://localhost:3000');
		expect(toServerUrl('HTTPS://Relay.example.com//')).toBe('HTTPS://Relay.example.com');
	});

	it('rejects empty input and other schemes', () => {
		expect(toServerUrl('')).toBeNull();
		expect(toServerUrl('   ')).toBeNull();
		expect(toServerUrl('ftp://example.com')).toBeNull();
		expect(toServerUrl('https://')).toBeNull();
		expect(toServerUrl('https:')).toBeNull();
		expect(toServerUrl('mailto:me@example.com')).toBeNull();
	});

	it('accepts a bare host with a port', () => {
		expect(toServerUrl('localhost:3000')).toBe('https://localhost:3000');
	});
});

describe('serverHost', () => {
	it('shows the host of a URL and tolerates junk', () => {
		expect(serverHost('https://cpmesh.example.com:8443/path')).toBe('cpmesh.example.com:8443');
		expect(serverHost('not a url/')).toBe('not a url');
		expect(serverHost(undefined)).toBe('');
	});
});

describe('fingerprintGroups', () => {
	it('splits the full fingerprint into groups of four, keeping every character', () => {
		const fingerprint = 'ab12'.repeat(16);
		const groups = fingerprintGroups(fingerprint);
		expect(groups).toHaveLength(16);
		expect(groups.join('')).toBe(fingerprint.toUpperCase());
	});

	it('ignores the separators the backend also ignores', () => {
		expect(fingerprintGroups('ab:cd-ef 12 34')).toEqual(['ABCD', 'EF12', '34']);
	});
});

describe('formatting', () => {
	const now = new Date('2026-10-16T12:00:00Z').getTime();

	it('formats relative times', () => {
		expect(formatRelative(undefined, now)).toBe('Never');
		expect(formatRelative(now - 10_000, now)).toBe('Just now');
		expect(formatRelative(now - 5 * 60_000, now)).toBe('5 min ago');
		expect(formatRelative(now - 3 * 3_600_000, now)).toBe('3 h ago');
		expect(formatRelative(now - 2 * 86_400_000, now)).toBe('2 d ago');
		expect(formatRelative('garbage', now)).toBe('—');
	});

	it('labels days for grouping', () => {
		const today = new Date(2026, 9, 16, 15, 0);
		expect(dayLabel(new Date(2026, 9, 16, 8, 0).getTime(), today)).toBe('Today');
		expect(dayLabel(new Date(2026, 9, 15, 23, 0).getTime(), today)).toBe('Yesterday');
		expect(dayLabel(new Date(2026, 9, 1).getTime(), today)).not.toMatch(/Today|Yesterday/);
		expect(dayLabel('garbage', today)).toBe('Earlier');
	});

	it('formats sizes', () => {
		expect(formatSize(512)).toBe('512 B');
		expect(formatSize(2048)).toBe('2.0 KB');
		expect(formatSize(3 * 1_048_576)).toBe('3.0 MB');
	});

	it('classifies content and devices', () => {
		expect(contentKind('text')).toBe('text');
		expect(contentKind('image')).toBe('image');
		expect(contentKind('image/png')).toBe('image');
		expect(contentKind('file')).toBe('file');
		expect(deviceIcon('Android')).toBe('smartphone');
		expect(deviceIcon('macOS - studio')).toBe('laptop');
		expect(deviceIcon('Windows - desk')).toBe('monitor');
	});

	it('reads messages from command errors', () => {
		expect(errorMessage('Login failed: nope')).toBe('Login failed: nope');
		expect(errorMessage(new Error('boom'))).toBe('boom');
		expect(errorMessage({ message: 'structured', restart: false })).toBe('structured');
		expect(errorMessage(42)).toBe('42');
	});
});

describe('shortcutKeys', () => {
	afterEach(() => vi.unstubAllGlobals());

	it('spells modifiers for macOS', () => {
		vi.stubGlobal('navigator', { platform: 'MacIntel', userAgent: '' });
		expect(shortcutKeys(['mod', 'shift', 'Space'])).toEqual(['⌘', '⇧', 'Space']);
	});

	it('spells modifiers elsewhere', () => {
		vi.stubGlobal('navigator', { platform: 'Win32', userAgent: '' });
		expect(shortcutKeys(['mod', 'alt', 'K'])).toEqual(['Ctrl', 'Alt', 'K']);
	});
});

describe('remembered server', () => {
	afterEach(() => vi.unstubAllGlobals());

	it('remembers and forgets the last server', () => {
		const store = new Map<string, string>();
		vi.stubGlobal('localStorage', {
			getItem: (k: string) => store.get(k) ?? null,
			setItem: (k: string, v: string) => store.set(k, v),
			removeItem: (k: string) => store.delete(k),
		});
		expect(getLastServerUrl()).toBe('');
		rememberServerUrl('https://relay.example.com');
		expect(getLastServerUrl()).toBe('https://relay.example.com');
		rememberServerUrl('');
		expect(getLastServerUrl()).toBe('https://relay.example.com');
		forgetServerUrl();
		expect(getLastServerUrl()).toBe('');
	});

	it('copes without storage', () => {
		vi.stubGlobal('localStorage', undefined);
		expect(getLastServerUrl()).toBe('');
		expect(() => rememberServerUrl('https://x')).not.toThrow();
		expect(() => forgetServerUrl()).not.toThrow();
	});
});
