import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { isPermissionGranted, requestPermission, sendNotification } from '@tauri-apps/plugin-notification';
import { getStatus, type StatusInfo, type HistoryEntry, type UpdateInfo } from './api';

// App state
let appState = $state<string>('not_configured');
let status = $state<StatusInfo | null>(null);
let recentEntry = $state<HistoryEntry | null>(null);
let syncError = $state('');

export function getSyncError() { return syncError; }

export function clearSyncError() {
	syncError = '';
}

// Devices waiting for approval, badged in the navigation
let pendingDeviceCount = $state(0);

export function getPendingDeviceCount() {
	return pendingDeviceCount;
}

export function setPendingDeviceCount(count: number) {
	pendingDeviceCount = count;
}

// What happened during this session, newest first, for the overview timeline
export type ActivityKind = 'connected' | 'disconnected' | 'device-online' | 'device-offline' | 'sync-error';

export interface ActivityEvent {
	id: number;
	kind: ActivityKind;
	label: string;
	at: number;
}

const MAX_ACTIVITY = 30;
let activity = $state<ActivityEvent[]>([]);
let nextActivityId = 1;

export function getActivity() {
	return activity;
}

function recordActivity(kind: ActivityKind, label: string) {
	activity = [{ id: nextActivityId++, kind, label, at: Date.now() }, ...activity].slice(0, MAX_ACTIVITY);
}

// Update state
let availableUpdate = $state<UpdateInfo | null>(null);
let lastDismissedVersion = $state<string>('');

// Listener cleanup
let unlistenFns: UnlistenFn[] = [];
let listenersInitialized = false;

// Dedup in-flight refreshStatus
let refreshPromise: Promise<void> | null = null;

export function getAppStateValue() {
	return appState;
}

export function getStatusValue() {
	return status;
}

export function getRecentEntry() {
	return recentEntry;
}

export function setAppState(s: string) {
	appState = s;
}

export function getAvailableUpdate() {
	return availableUpdate;
}

export function dismissUpdate() {
	if (availableUpdate) {
		lastDismissedVersion = availableUpdate.version;
	}
	availableUpdate = null;
}

export async function refreshStatus() {
	if (refreshPromise) return refreshPromise;
	refreshPromise = (async () => {
		try {
			status = await getStatus();
			appState = status.state;
		} catch {
			// ignore during init
		} finally {
			refreshPromise = null;
		}
	})();
	return refreshPromise;
}

// Listen for backend events — idempotent, returns cleanup function
export function initEventListeners(): () => void {
	if (listenersInitialized) return destroyEventListeners;
	listenersInitialized = true;

	listen<string>('connection-state-changed', (event) => {
		const previous = appState;
		appState = event.payload as string;
		if (appState === 'connected' || appState === 'not_configured') syncError = '';
		if (appState !== previous) {
			if (appState === 'connected') recordActivity('connected', 'Connected to the relay');
			else if (appState === 'disconnected' && previous === 'connected') recordActivity('disconnected', 'Disconnected from the relay');
		}
		refreshStatus();
	}).then((u) => unlistenFns.push(u));

	listen<string>('sync-error', (event) => {
		syncError = event.payload;
		recordActivity('sync-error', event.payload);
	}).then((u) => unlistenFns.push(u));

	listen<HistoryEntry>('clipboard-new', (event) => {
		recentEntry = event.payload;
	}).then((u) => unlistenFns.push(u));

	listen<{ device_name?: unknown; online?: unknown }>('device-status-changed', (event) => {
		const { device_name, online } = event.payload ?? {};
		if (typeof device_name === 'string' && typeof online === 'boolean') {
			recordActivity(online ? 'device-online' : 'device-offline', `${device_name} ${online ? 'came online' : 'went offline'}`);
		}
		refreshStatus();
	}).then((u) => unlistenFns.push(u));

	listen<UpdateInfo>('update-available', (event) => {
		// Don't show if user already dismissed this version
		if (event.payload.version === lastDismissedVersion) return;
		availableUpdate = event.payload;
		try {
			sendNotification({
				title: 'cpmesh Update Available',
				body: `Version ${event.payload.version} is ready to download.`,
			});
		} catch {
			// Non-fatal if notification fails
		}
	}).then((u) => unlistenFns.push(u));

	// Request notification permission (required on macOS)
	requestNotificationPermission();

	// Initial load
	refreshStatus();

	return destroyEventListeners;
}

export function destroyEventListeners() {
	for (const unsub of unlistenFns) unsub();
	unlistenFns = [];
	listenersInitialized = false;
}

async function requestNotificationPermission() {
	try {
		const granted = await isPermissionGranted();
		if (!granted) {
			await requestPermission();
		}
	} catch {
		// Non-fatal — notifications will silently fail if denied
	}
}
