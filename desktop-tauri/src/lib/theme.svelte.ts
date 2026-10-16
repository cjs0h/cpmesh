// Appearance: follows the system unless the user picks light or dark in Settings.

import { getCurrentWindow } from '@tauri-apps/api/window';

export type ThemePreference = 'system' | 'light' | 'dark';

const STORAGE_KEY = 'cpmesh.theme';

function readPreference(): ThemePreference {
	try {
		const stored = localStorage.getItem(STORAGE_KEY);
		if (stored === 'light' || stored === 'dark' || stored === 'system') return stored;
	} catch {
		// Storage unavailable
	}
	return 'system';
}

const themeState = $state({ preference: 'system' as ThemePreference, systemDark: false });

export function getThemePreference(): ThemePreference {
	return themeState.preference;
}

export function isDarkTheme(): boolean {
	return themeState.preference === 'dark' || (themeState.preference === 'system' && themeState.systemDark);
}

function apply() {
	const dark = isDarkTheme();
	const root = document.documentElement;
	root.classList.toggle('dark', dark);
	root.classList.toggle('light', !dark);
	// static/theme-init.js painted the first frame; the stylesheet takes over from here
	root.style.colorScheme = dark ? 'dark' : 'light';
	root.style.backgroundColor = '';
	// Keep the native title bar in step; `null` hands it back to the system
	const nativeTheme = themeState.preference === 'system' ? null : themeState.preference;
	try {
		getCurrentWindow().setTheme(nativeTheme).catch(() => {});
	} catch {
		// Not running inside Tauri
	}
}

export function setThemePreference(preference: ThemePreference) {
	themeState.preference = preference;
	try {
		localStorage.setItem(STORAGE_KEY, preference);
	} catch {
		// Storage unavailable; the choice lasts for this session
	}
	apply();
}

let initialized = false;

/** Applies the stored preference and follows system changes. Safe to call more than once. */
export function initTheme() {
	if (initialized || typeof window === 'undefined') return;
	initialized = true;
	themeState.preference = readPreference();
	const media = window.matchMedia('(prefers-color-scheme: dark)');
	themeState.systemDark = media.matches;
	media.addEventListener('change', (event) => {
		themeState.systemDark = event.matches;
		apply();
	});
	apply();
}
