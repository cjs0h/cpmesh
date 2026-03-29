// Platform detection utility for Tauri apps
// Uses navigator.userAgent to detect mobile vs desktop

function detectPlatform(): 'android' | 'ios' | 'desktop' {
	const ua = navigator.userAgent.toLowerCase();
	if (ua.includes('android')) return 'android';
	if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ipod')) return 'ios';
	return 'desktop';
}

const platform = detectPlatform();

export function isMobile(): boolean {
	return platform === 'android' || platform === 'ios';
}

export function isDesktop(): boolean {
	return platform === 'desktop';
}

export function isAndroid(): boolean {
	return platform === 'android';
}

export function isIOS(): boolean {
	return platform === 'ios';
}

export function getPlatform(): string {
	return platform;
}
