// Recovery shown outside any one page: an encryption key this device lacks, a newer
// version installed over the running one, and the helpers behind the screens that let
// people fix keys and registrations from inside the app.

import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import {
	getKeyProblem,
	updateInstalled,
	type AccountDevice,
	type KeyBackup,
	type KeyMember,
	type KeyProblem,
	type SignInAction,
} from './api';

export const recovery: {
	/** Set while this device lacks the account's current encryption key */
	keyProblem: KeyProblem | null;
	/** A newer cpmesh was installed while this one ran; it starts after a restart */
	updateInstalled: boolean;
	/** The Encryption keys dialog (KeyRecoveryDialog) */
	dialogOpen: boolean;
} = $state({ keyProblem: null, updateInstalled: false, dialogOpen: false });

export function openKeyRecovery() {
	recovery.dialogOpen = true;
}

export async function refreshKeyProblem() {
	try {
		recovery.keyProblem = await getKeyProblem();
	} catch {
		// Keep what we knew
	}
}

/** Follows the backend's key and update events; returns the cleanup. */
export function watchRecovery(): () => void {
	let disposed = false;
	const unlisteners: UnlistenFn[] = [];
	const track = (registration: Promise<UnlistenFn>) =>
		registration
			.then((unlisten) => {
				if (disposed) unlisten();
				else unlisteners.push(unlisten);
			})
			.catch(() => {});
	track(listen<KeyProblem | null>('key-problem-changed', (event) => (recovery.keyProblem = event.payload ?? null)));
	track(listen('update-installed', () => (recovery.updateInstalled = true)));
	refreshKeyProblem();
	updateInstalled()
		.then((installed) => {
			if (installed) recovery.updateInstalled = true;
		})
		.catch(() => {});
	return () => {
		disposed = true;
		for (const unlisten of unlisteners) unlisten();
	};
}

/** What replacing `oldId` as this computer's registration involves. */
export interface ReplacementPlan {
	old: AccountDevice;
	/** Approved devices that stay; one of them approves this computer afterwards */
	approvers: AccountDevice[];
	/**
	 * Devices removed along with it. The relay approves a registration by itself only on an
	 * account without devices, so with no approver left, waiting (and rejected) devices go too.
	 */
	waiting: AccountDevice[];
	/** The old registration may be the only holder of the account's encryption key */
	keysAtRisk: boolean;
	action: SignInAction;
}

export function replacementPlan(devices: AccountDevice[], oldId: string | null): ReplacementPlan | null {
	const old = devices.find((device) => device.id === oldId);
	if (!old) return null;
	const others = devices.filter((device) => device.id !== old.id);
	const approvers = others.filter((device) => device.status === 'approved');
	const waiting = approvers.length === 0 ? others : [];
	return {
		old,
		approvers,
		waiting,
		keysAtRisk: old.status === 'approved' && approvers.length === 0,
		action: { action: 'replace_device', device_id: old.id, waiting_device_ids: waiting.map((device) => device.id) },
	};
}

/** "Alice", "Alice and Bob", "Alice, Bob and Carol" */
export function listNames(names: string[]): string {
	if (names.length <= 1) return names[0] ?? '';
	return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}

/** "key 3", "keys 1–4", "keys 1, 3 and 5" */
export function describeVersions(versions: number[]): string {
	const sorted = [...versions].sort((a, b) => a - b);
	if (sorted.length === 0) return 'no keys';
	if (sorted.length === 1) return `key ${sorted[0]}`;
	const contiguous = sorted.every((version, i) => i === 0 || version === sorted[i - 1] + 1);
	if (contiguous) return `keys ${sorted[0]}–${sorted[sorted.length - 1]}`;
	return `keys ${listNames(sorted.map(String))}`;
}

/** Whether `backup` can be restored at all. */
export function isRestorable(backup: KeyBackup): boolean {
	return backup.problem === null && backup.versions.length > 0;
}

/** Whether `backup` can be restored and holds the key version this device is missing. */
export function holdsMissingKey(backup: KeyBackup, problem: KeyProblem | null): boolean {
	return problem !== null && isRestorable(backup) && backup.versions.includes(problem.server_version);
}

/** Backups that can fix the missing key first, then other restorable ones, then the rest. */
export function sortBackups(backups: KeyBackup[], problem: KeyProblem | null): KeyBackup[] {
	const rank = (backup: KeyBackup) => (holdsMissingKey(backup, problem) ? 0 : isRestorable(backup) ? 1 : 2);
	return [...backups].sort((a, b) => rank(a) - rank(b));
}

/**
 * Devices a new key can't reach yet: starting new keys wraps one for every approved device,
 * and only to devices verified here that run an up-to-date cpmesh.
 */
export function resetBlockers(devices: KeyMember[]): KeyMember[] {
	return devices.filter((device) => !device.verified || !device.can_receive_keys);
}
