import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AccountDevice, KeyBackup, KeyMember } from './api';

type Handler = (event: { payload: unknown }) => void;

const mocks = vi.hoisted(() => ({
	invoke: vi.fn(),
	listen: vi.fn(),
	handlers: new Map<string, Handler>(),
}));

vi.mock('@tauri-apps/api/core', () => ({ invoke: mocks.invoke }));
vi.mock('@tauri-apps/api/event', () => ({ listen: mocks.listen }));

type RecoveryModule = typeof import('./recovery.svelte.js');

function device(id: string, status: AccountDevice['status'], name = id): AccountDevice {
	return { id, name, status, last_seen: null, online: false };
}

function backup(overrides: Partial<KeyBackup> = {}): KeyBackup {
	return {
		path: '/data/backups/keys-1',
		name: 'keys-1',
		created_at: null,
		reason: null,
		owner_server: null,
		same_account: null,
		versions: [1, 2],
		problem: null,
		...overrides,
	};
}

async function flush() {
	await new Promise((resolve) => setTimeout(resolve, 0));
}

describe('recovery', () => {
	let recovery: RecoveryModule;

	beforeEach(async () => {
		mocks.invoke.mockReset();
		mocks.listen.mockReset();
		mocks.handlers.clear();
		mocks.listen.mockImplementation(async (event: string, handler: Handler) => {
			mocks.handlers.set(event, handler);
			return vi.fn();
		});
		// Module-level $state is shared, so every test gets a fresh module instance
		vi.resetModules();
		recovery = await import('./recovery.svelte.js');
	});

	describe('replacing this computer’s old registration', () => {
		it('leaves other devices alone when one of them can approve this computer', () => {
			const plan = recovery.replacementPlan(
				[device('old', 'approved', 'Linux - box'), device('mac', 'approved'), device('phone', 'pending')],
				'old',
			);
			expect(plan?.approvers.map((d) => d.id)).toEqual(['mac']);
			expect(plan?.waiting).toEqual([]);
			expect(plan?.keysAtRisk).toBe(false);
			expect(plan?.action).toEqual({ action: 'replace_device', device_id: 'old', waiting_device_ids: [] });
		});

		it('removes waiting devices too when no approver would be left, and warns about the keys', () => {
			const plan = recovery.replacementPlan([device('old', 'approved'), device('mac', 'pending'), device('x', 'rejected')], 'old');
			expect(plan?.approvers).toEqual([]);
			expect(plan?.waiting.map((d) => d.id)).toEqual(['mac', 'x']);
			expect(plan?.keysAtRisk).toBe(true);
			expect(plan?.action).toEqual({ action: 'replace_device', device_id: 'old', waiting_device_ids: ['mac', 'x'] });
		});

		it('only warns about keys an approved registration could hold', () => {
			expect(recovery.replacementPlan([device('old', 'pending')], 'old')?.keysAtRisk).toBe(false);
		});

		it('needs a registration to replace', () => {
			expect(recovery.replacementPlan([device('a', 'approved')], null)).toBeNull();
			expect(recovery.replacementPlan([device('a', 'approved')], 'missing')).toBeNull();
		});
	});

	it('lists names and key versions the way people read them', () => {
		expect(recovery.listNames([])).toBe('');
		expect(recovery.listNames(['Mac'])).toBe('Mac');
		expect(recovery.listNames(['Mac', 'Phone'])).toBe('Mac and Phone');
		expect(recovery.listNames(['Mac', 'Phone', 'Linux'])).toBe('Mac, Phone and Linux');

		expect(recovery.describeVersions([])).toBe('no keys');
		expect(recovery.describeVersions([3])).toBe('key 3');
		expect(recovery.describeVersions([4, 2, 3])).toBe('keys 2–4');
		expect(recovery.describeVersions([1, 3, 5])).toBe('keys 1, 3 and 5');
	});

	it('offers the backups that fix the missing key first', () => {
		const problem = { server_version: 4, shared_by: null };
		const fixes = backup({ path: '/a', versions: [3, 4] });
		const older = backup({ path: '/b', versions: [1, 2] });
		const unreadable = backup({ path: '/c', versions: [], problem: 'Neither key opens it' });
		const foreign = backup({ path: '/d', versions: [4], same_account: false, problem: 'Another account' });

		expect(recovery.isRestorable(fixes)).toBe(true);
		expect(recovery.isRestorable(unreadable)).toBe(false);
		expect(recovery.holdsMissingKey(fixes, problem)).toBe(true);
		expect(recovery.holdsMissingKey(older, problem)).toBe(false);
		expect(recovery.holdsMissingKey(fixes, null)).toBe(false);
		// Another account's key 4 is not this account's
		expect(recovery.holdsMissingKey(foreign, problem)).toBe(false);
		expect(recovery.sortBackups([unreadable, older, foreign, fixes], problem).map((b) => b.path)).toEqual([
			'/a',
			'/b',
			'/c',
			'/d',
		]);
	});

	it('names the devices a new key cannot reach yet', () => {
		const devices: KeyMember[] = [
			{ id: 'ok', name: 'Mac', verified: true, trust: 'verified', can_receive_keys: true, has_current_key: true },
			{ id: 'unverified', name: 'Phone', verified: false, trust: 'unverified', can_receive_keys: true, has_current_key: true },
			{ id: 'outdated', name: 'Old', verified: true, trust: 'verified', can_receive_keys: false, has_current_key: null },
		];
		expect(recovery.resetBlockers(devices).map((d) => d.id)).toEqual(['unverified', 'outdated']);
		expect(recovery.resetBlockers([])).toEqual([]);
	});

	it('follows the key problem and installed updates the backend reports', async () => {
		mocks.invoke.mockImplementation(async (command: string) => (command === 'get_key_problem' ? { server_version: 4, shared_by: null } : false));
		const stop = recovery.watchRecovery();
		await flush();
		expect(mocks.invoke).toHaveBeenCalledWith('get_key_problem');
		expect(mocks.invoke).toHaveBeenCalledWith('update_installed');
		expect(recovery.recovery.keyProblem).toEqual({ server_version: 4, shared_by: null });
		expect(recovery.recovery.updateInstalled).toBe(false);

		mocks.handlers.get('key-problem-changed')?.({ payload: null });
		expect(recovery.recovery.keyProblem).toBeNull();
		mocks.handlers.get('update-installed')?.({ payload: null });
		expect(recovery.recovery.updateInstalled).toBe(true);
		stop();

		recovery.openKeyRecovery();
		expect(recovery.recovery.dialogOpen).toBe(true);
	});
});
