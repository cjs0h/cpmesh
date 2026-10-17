// Small helpers shared by the redesigned screens: formatting, keyboard labels,
// remembered values and device presentation.

const LAST_SERVER_KEY = 'cpmesh.lastServerUrl';

/** The server the user last signed in to, offered again after signing out. */
export function getLastServerUrl(): string {
	try {
		return localStorage.getItem(LAST_SERVER_KEY) ?? '';
	} catch {
		return '';
	}
}

export function rememberServerUrl(url: string) {
	if (!url) return;
	try {
		localStorage.setItem(LAST_SERVER_KEY, url);
	} catch {
		// Storage unavailable
	}
}

/** Starts the next sign-in with an empty server address (e.g. when switching servers). */
export function forgetServerUrl() {
	try {
		localStorage.removeItem(LAST_SERVER_KEY);
	} catch {
		// Storage unavailable
	}
}

/** Host part of a server URL for compact display; falls back to the input. */
export function serverHost(url: string | null | undefined): string {
	if (!url) return '';
	try {
		return new URL(url).host;
	} catch {
		return url.replace(/^https?:\/\//, '').replace(/\/+$/, '');
	}
}

/**
 * Turns what the user typed into a server URL: trims, drops trailing slashes and
 * assumes https:// when no scheme was given. Returns null when it cannot be a URL.
 */
export function toServerUrl(input: string): string | null {
	let value = input.trim();
	if (!value) return null;
	if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
		// A scheme without "//" (e.g. "https:"), as opposed to host:port
		if (/^[a-z][a-z0-9+.-]*:(?!\d)/i.test(value)) return null;
		value = `https://${value}`;
	}
	value = value.replace(/\/+$/, '');
	try {
		const url = new URL(value);
		if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
		if (!url.hostname) return null;
		return value;
	} catch {
		return null;
	}
}

export function isMacLike(): boolean {
	if (typeof navigator === 'undefined') return false;
	return /Mac|iPhone|iPad|iPod/i.test(navigator.platform || navigator.userAgent);
}

export function isWindowsLike(): boolean {
	if (typeof navigator === 'undefined') return false;
	return /Win32|Win64|Windows/i.test(navigator.platform || navigator.userAgent);
}

/**
 * Key labels for a shortcut like ['mod', 'shift', 'Space'] on the current platform:
 * 'mod' is ⌘ or Ctrl, 'ctrl' is ⌃ on macOS, 'super' the Windows or Super key.
 */
export function shortcutKeys(keys: string[], mac = isMacLike()): string[] {
	return keys.map((key) => {
		switch (key) {
			case 'mod':
				return mac ? '⌘' : 'Ctrl';
			case 'ctrl':
				return mac ? '⌃' : 'Ctrl';
			case 'shift':
				return mac ? '⇧' : 'Shift';
			case 'alt':
				return mac ? '⌥' : 'Alt';
			case 'super':
				return mac ? '⌘' : isWindowsLike() ? 'Win' : 'Super';
			default:
				return key;
		}
	});
}

/** Whether the platform's primary modifier (Cmd on macOS, Ctrl elsewhere) is held. */
export function hasModKey(event: KeyboardEvent): boolean {
	return isMacLike() ? event.metaKey : event.ctrlKey;
}

export function formatRelative(iso: string | number | undefined, now = Date.now()): string {
	if (iso === undefined || iso === '') return 'Never';
	const time = typeof iso === 'number' ? iso : new Date(iso).getTime();
	if (Number.isNaN(time)) return '—';
	const diff = now - time;
	if (diff < 45_000) return 'Just now';
	if (diff < 3_600_000) return `${Math.max(1, Math.floor(diff / 60_000))} min ago`;
	if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} h ago`;
	if (diff < 7 * 86_400_000) return `${Math.floor(diff / 86_400_000)} d ago`;
	return new Date(time).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

export function formatClock(iso: string | number): string {
	const date = new Date(iso);
	if (Number.isNaN(date.getTime())) return '';
	return date.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
}

/** "Today", "Yesterday" or a date, for grouping a timeline by day. */
export function dayLabel(iso: string | number, now = new Date()): string {
	const date = new Date(iso);
	if (Number.isNaN(date.getTime())) return 'Earlier';
	const startOf = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
	const days = Math.round((startOf(now) - startOf(date)) / 86_400_000);
	if (days <= 0) return 'Today';
	if (days === 1) return 'Yesterday';
	return date.toLocaleDateString(undefined, {
		weekday: days < 7 ? 'long' : undefined,
		month: 'long',
		day: 'numeric',
		year: date.getFullYear() === now.getFullYear() ? undefined : 'numeric',
	});
}

export function formatSize(bytes: number): string {
	if (bytes < 1024) return `${bytes} B`;
	if (bytes < 1_048_576) return `${(bytes / 1024).toFixed(1)} KB`;
	return `${(bytes / 1_048_576).toFixed(1)} MB`;
}

export type ContentKind = 'text' | 'image' | 'file';

export function contentKind(type: string): ContentKind {
	if (type === 'image' || type.startsWith('image/')) return 'image';
	if (type === 'file') return 'file';
	return 'text';
}

/** Icon name for a device, guessed from the platform its name starts with. */
export function deviceIcon(name: string): string {
	const n = name.toLowerCase();
	if (n.startsWith('android') || n.startsWith('ios') || n.includes('iphone')) return 'smartphone';
	if (n.includes('ipad') || n.includes('tablet')) return 'tablet';
	if (n.startsWith('linux') || n.startsWith('windows')) return 'monitor';
	return 'laptop';
}

/** Splits a fingerprint into groups of four for side-by-side comparison. */
export function fingerprintGroups(fingerprint: string): string[] {
	const compact = fingerprint.replace(/[\s:-]/g, '').toUpperCase();
	return compact.match(/.{1,4}/g) ?? [];
}

/** Readable message from an error thrown by a Tauri command. */
export function errorMessage(error: unknown): string {
	if (typeof error === 'string') return error;
	if (error instanceof Error) return error.message;
	if (typeof error === 'object' && error !== null && typeof (error as { message?: unknown }).message === 'string') {
		return (error as { message: string }).message;
	}
	return String(error);
}
