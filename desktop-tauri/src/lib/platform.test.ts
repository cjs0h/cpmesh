import { beforeEach, describe, expect, it, vi } from 'vitest';

type PlatformModule = typeof import('./platform.js');

// Platform detection runs once at module load, so each case imports a fresh copy.
async function loadWithUserAgent(userAgent: string): Promise<PlatformModule> {
	vi.stubGlobal('navigator', { userAgent });
	vi.resetModules();
	return import('./platform.js');
}

describe('platform detection', () => {
	beforeEach(() => {
		vi.unstubAllGlobals();
	});

	it('detects Android', async () => {
		const p = await loadWithUserAgent(
			'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36',
		);
		expect(p.getPlatform()).toBe('android');
		expect(p.isAndroid()).toBe(true);
		expect(p.isIOS()).toBe(false);
		expect(p.isMobile()).toBe(true);
		expect(p.isDesktop()).toBe(false);
	});

	it.each([
		'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
		'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
		'Mozilla/5.0 (iPod touch; CPU iPhone OS 15_0 like Mac OS X)',
	])('detects iOS devices: %s', async (ua) => {
		const p = await loadWithUserAgent(ua);
		expect(p.getPlatform()).toBe('ios');
		expect(p.isIOS()).toBe(true);
		expect(p.isMobile()).toBe(true);
		expect(p.isDesktop()).toBe(false);
	});

	it.each([
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36 Edg/120',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15',
		'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36',
	])('treats everything else as desktop: %s', async (ua) => {
		const p = await loadWithUserAgent(ua);
		expect(p.getPlatform()).toBe('desktop');
		expect(p.isDesktop()).toBe(true);
		expect(p.isMobile()).toBe(false);
		expect(p.isAndroid()).toBe(false);
		expect(p.isIOS()).toBe(false);
	});

	it('is case-insensitive', async () => {
		const p = await loadWithUserAgent('ANDROID-WEBVIEW');
		expect(p.isAndroid()).toBe(true);
	});
});
