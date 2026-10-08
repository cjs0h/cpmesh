import { beforeEach, describe, expect, it, vi } from 'vitest';

type Handler = (event: { payload: unknown }) => void;

const mocks = vi.hoisted(() => ({
	invoke: vi.fn(),
	listen: vi.fn(),
	isPermissionGranted: vi.fn(),
	requestPermission: vi.fn(),
	sendNotification: vi.fn(),
	handlers: new Map<string, Handler>(),
	unlisteners: [] as Array<ReturnType<typeof vi.fn>>,
}));

vi.mock('@tauri-apps/api/core', () => ({ invoke: mocks.invoke }));
vi.mock('@tauri-apps/api/event', () => ({
	listen: mocks.listen,
}));
vi.mock('@tauri-apps/plugin-notification', () => ({
	isPermissionGranted: mocks.isPermissionGranted,
	requestPermission: mocks.requestPermission,
	sendNotification: mocks.sendNotification,
}));

type StoreModule = typeof import('./store.svelte.js');

const status = {
	state: 'connected',
	server_url: 'https://s',
	device_name: 'Laptop',
	device_count: 2,
	online_count: 1,
};

function emit(event: string, payload: unknown) {
	const handler = mocks.handlers.get(event);
	if (!handler) throw new Error(`no listener registered for ${event}`);
	handler({ payload });
}

async function flush() {
	// A macrotask turn lets listen().then(...) and refreshStatus() settle fully
	await new Promise((resolve) => setTimeout(resolve, 0));
}

describe('desktop app store', () => {
	let store: StoreModule;

	beforeEach(async () => {
		mocks.invoke.mockReset();
		mocks.listen.mockReset();
		mocks.isPermissionGranted.mockReset();
		mocks.requestPermission.mockReset();
		mocks.sendNotification.mockReset();
		mocks.handlers.clear();
		mocks.unlisteners = [];

		mocks.invoke.mockResolvedValue(status);
		mocks.isPermissionGranted.mockResolvedValue(true);
		mocks.listen.mockImplementation(async (event: string, handler: Handler) => {
			mocks.handlers.set(event, handler);
			const unlisten = vi.fn();
			mocks.unlisteners.push(unlisten);
			return unlisten;
		});

		// Module-level $state is shared, so every test gets a fresh module instance
		vi.resetModules();
		store = await import('./store.svelte.js');
	});

	it('starts unconfigured with no status', () => {
		expect(store.getAppStateValue()).toBe('not_configured');
		expect(store.getStatusValue()).toBeNull();
		expect(store.getRecentEntry()).toBeNull();
		expect(store.getAvailableUpdate()).toBeNull();
	});

	it('refreshStatus loads status and derives the app state', async () => {
		await store.refreshStatus();
		expect(mocks.invoke).toHaveBeenCalledWith('get_status');
		expect(store.getStatusValue()).toEqual(status);
		expect(store.getAppStateValue()).toBe('connected');
	});

	it('refreshStatus deduplicates concurrent calls and swallows errors', async () => {
		let resolveStatus!: (s: typeof status) => void;
		mocks.invoke.mockReturnValueOnce(new Promise((r) => (resolveStatus = r)));

		const a = store.refreshStatus();
		const b = store.refreshStatus();
		expect(mocks.invoke).toHaveBeenCalledTimes(1);
		resolveStatus(status);
		await Promise.all([a, b]);
		expect(store.getAppStateValue()).toBe('connected');

		mocks.invoke.mockRejectedValueOnce(new Error('backend not ready'));
		await expect(store.refreshStatus()).resolves.toBeUndefined();
		expect(store.getAppStateValue()).toBe('connected');

		// A new refresh is possible after the previous one settled
		mocks.invoke.mockResolvedValueOnce({ ...status, state: 'disconnected' });
		await store.refreshStatus();
		expect(store.getAppStateValue()).toBe('disconnected');
	});

	it('setAppState overrides the current state', () => {
		store.setAppState('connecting');
		expect(store.getAppStateValue()).toBe('connecting');
	});

	it('initEventListeners registers backend listeners once and loads status', async () => {
		const cleanup = store.initEventListeners();
		const again = store.initEventListeners();
		await flush();

		expect(again).toBe(cleanup);
		expect(mocks.listen).toHaveBeenCalledTimes(4);
		expect([...mocks.handlers.keys()].sort()).toEqual(
			['clipboard-new', 'connection-state-changed', 'device-status-changed', 'update-available'].sort(),
		);
		expect(mocks.invoke).toHaveBeenCalledWith('get_status');
		expect(mocks.isPermissionGranted).toHaveBeenCalled();
		expect(mocks.requestPermission).not.toHaveBeenCalled();
	});

	it('requests notification permission when not yet granted', async () => {
		mocks.isPermissionGranted.mockResolvedValue(false);
		store.initEventListeners();
		await flush();
		expect(mocks.requestPermission).toHaveBeenCalledTimes(1);
	});

	it('reacts to backend events', async () => {
		store.initEventListeners();
		await flush();
		mocks.invoke.mockClear();

		emit('connection-state-changed', 'disconnected');
		expect(store.getAppStateValue()).toBe('disconnected');
		expect(mocks.invoke).toHaveBeenCalledWith('get_status');
		// The status refresh is in flight; a second trigger before it settles is deduplicated
		mocks.invoke.mockClear();
		emit('device-status-changed', {});
		expect(mocks.invoke).not.toHaveBeenCalled();
		await flush();
		expect(store.getAppStateValue()).toBe('connected');

		const entry = { id: 'e1', device_name: 'Phone', content_type: 'text', preview: 'hi', size: 2, created_at: 'now' };
		emit('clipboard-new', entry);
		expect(store.getRecentEntry()).toEqual(entry);

		mocks.invoke.mockClear();
		emit('device-status-changed', {});
		expect(mocks.invoke).toHaveBeenCalledWith('get_status');
	});

	it('surfaces available updates with a notification and honours dismissal', async () => {
		store.initEventListeners();
		await flush();

		const update = { update_available: true, version: '0.2.0', download_url: 'https://dl', release_notes: 'notes' };
		emit('update-available', update);
		expect(store.getAvailableUpdate()).toEqual(update);
		expect(mocks.sendNotification).toHaveBeenCalledWith({
			title: 'cpmesh Update Available',
			body: 'Version 0.2.0 is ready to download.',
		});

		store.dismissUpdate();
		expect(store.getAvailableUpdate()).toBeNull();

		// The same version is not shown again once dismissed...
		mocks.sendNotification.mockClear();
		emit('update-available', update);
		expect(store.getAvailableUpdate()).toBeNull();
		expect(mocks.sendNotification).not.toHaveBeenCalled();

		// ...but a newer version is
		emit('update-available', { ...update, version: '0.3.0' });
		expect(store.getAvailableUpdate()?.version).toBe('0.3.0');
	});

	it('does not fail when notifications are unavailable', async () => {
		mocks.sendNotification.mockImplementation(() => {
			throw new Error('no notification backend');
		});
		store.initEventListeners();
		await flush();
		expect(() =>
			emit('update-available', { update_available: true, version: '1.0.0', download_url: '', release_notes: '' }),
		).not.toThrow();
		expect(store.getAvailableUpdate()?.version).toBe('1.0.0');
	});

	it('dismissUpdate is a no-op without a pending update', () => {
		expect(() => store.dismissUpdate()).not.toThrow();
		expect(store.getAvailableUpdate()).toBeNull();
	});

	it('destroyEventListeners unsubscribes and allows re-initialisation', async () => {
		const cleanup = store.initEventListeners();
		await flush();
		expect(mocks.unlisteners).toHaveLength(4);

		cleanup();
		for (const unlisten of mocks.unlisteners) expect(unlisten).toHaveBeenCalledTimes(1);

		mocks.listen.mockClear();
		store.initEventListeners();
		await flush();
		expect(mocks.listen).toHaveBeenCalledTimes(4);
	});
});
