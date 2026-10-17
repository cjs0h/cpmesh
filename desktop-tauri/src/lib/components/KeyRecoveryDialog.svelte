<script lang="ts">
	import { untrack } from 'svelte';
	import {
		connectToServer,
		getKeyRecoveryStatus,
		getOwnIdentity,
		inspectKeyBackup,
		removeDevice,
		resetEncryption,
		restoreKeyBackup,
		syncHistory,
		verifyDeviceIdentity,
		type KeyBackup,
		type KeyMember,
		type KeyRecoveryStatus,
	} from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import {
		describeVersions,
		holdsMissingKey,
		isRestorable,
		listNames,
		recovery,
		refreshKeyProblem,
		resetBlockers,
		sortBackups,
	} from '#lib/recovery.svelte.js';
	import { getAppStateValue, getStatusValue } from '#lib/store.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import { errorMessage, formatRelative } from '#lib/ui.js';
	import Alert from './ui/Alert.svelte';
	import Badge from './ui/Badge.svelte';
	import Button from './ui/Button.svelte';
	import Dialog from './ui/Dialog.svelte';
	import Field from './ui/Field.svelte';
	import Fingerprint from './ui/Fingerprint.svelte';
	import Skeleton from './ui/Skeleton.svelte';

	/*
	 * Encryption keys: get the current key from another device, restore keys from a backup
	 * (one cpmesh made when it set keys aside, or a folder the user points to), or, as the
	 * last resort, start new ones. Rendered once in the layout; open it with openKeyRecovery().
	 */

	let status = $state<KeyRecoveryStatus | null>(null);
	let loadError = $state('');
	let ownFingerprint = $state('');
	let busyPath = $state<string | null>(null);
	let otherFolder = $state('');
	let checkedFolder = $state<KeyBackup | null>(null);
	let checking = $state(false);
	let understood = $state(false);
	let resetting = $state(false);

	// Verifying or removing the other approved devices before starting new keys
	let verifyingId = $state<string | null>(null);
	let peerFingerprint = $state('');
	let verifyError = $state('');
	let memberBusy = $state<string | null>(null);

	const problem = $derived(status ? status.problem : recovery.keyProblem);
	const backups = $derived(status ? sortBackups(status.backups, problem) : []);
	const blockers = $derived(status ? resetBlockers(status.devices) : []);
	const busy = $derived(busyPath !== null || resetting || memberBusy !== null);
	const thisDevice = $derived(getStatusValue()?.device_name || 'this device');
	const canReset = $derived(
		Boolean(problem && status && !status.devices_error && blockers.length === 0 && understood),
	);

	$effect(() => {
		if (recovery.dialogOpen) untrack(() => load());
	});

	async function load() {
		loadError = '';
		understood = false;
		verifyingId = null;
		try {
			status = await getKeyRecoveryStatus();
			recovery.keyProblem = status.problem;
		} catch (e) {
			loadError = errorMessage(e);
		}
		if (!ownFingerprint) {
			getOwnIdentity()
				.then((identity) => (ownFingerprint = identity.fingerprint))
				.catch(() => {});
		}
	}

	// Syncing picks the keys up: reconnect, or read history again when already connected
	async function resume() {
		try {
			if (getAppStateValue() === 'connected') await syncHistory();
			else await connectToServer();
		} catch (e) {
			toast.error('Couldn’t sync yet', errorMessage(e));
		}
		await refreshKeyProblem();
		await load();
	}

	async function restore(backup: KeyBackup) {
		const confirmed = await confirmAction({
			title: 'Restore these keys?',
			description: `cpmesh adds ${describeVersions(backup.versions)} from “${backup.name}” to this device and keeps every key it already has. Only restore keys from your own devices.`,
			confirmLabel: 'Restore keys',
		});
		if (!confirmed) return;
		busyPath = backup.path;
		try {
			const restored = await restoreKeyBackup(backup.path);
			if (restored.added.length > 0) {
				toast.success(`Restored ${describeVersions(restored.added)}`, 'Syncing with them now.');
			} else {
				toast.info('Nothing new to restore', 'This device already had every key in that backup.');
			}
			checkedFolder = null;
			await resume();
		} catch (e) {
			toast.error('Couldn’t restore the keys', errorMessage(e));
		} finally {
			busyPath = null;
		}
	}

	async function checkFolder(event: SubmitEvent) {
		event.preventDefault();
		const path = otherFolder.trim();
		if (!path) return;
		checking = true;
		try {
			checkedFolder = await inspectKeyBackup(path);
		} catch (e) {
			checkedFolder = null;
			toast.error('Couldn’t check that folder', errorMessage(e));
		} finally {
			checking = false;
		}
	}

	function startVerifying(device: KeyMember) {
		verifyingId = device.id;
		peerFingerprint = '';
		verifyError = '';
	}

	async function verify(event: SubmitEvent, device: KeyMember) {
		event.preventDefault();
		memberBusy = device.id;
		verifyError = '';
		try {
			await verifyDeviceIdentity(device.id, peerFingerprint);
			toast.success(`${device.name} verified`);
			verifyingId = null;
			await load();
		} catch (e) {
			verifyError = errorMessage(e);
		} finally {
			memberBusy = null;
		}
	}

	async function remove(device: KeyMember) {
		const confirmed = await confirmAction({
			title: `Remove “${device.name}”?`,
			description: 'It stops syncing right away and has to be approved again to rejoin. Remove only devices you no longer use or can’t reach.',
			confirmLabel: 'Remove device',
			tone: 'danger',
		});
		if (!confirmed) return;
		memberBusy = device.id;
		try {
			await removeDevice(device.id);
			toast.success(`${device.name} removed`);
			await load();
		} catch (e) {
			toast.error('Couldn’t remove the device', errorMessage(e));
		} finally {
			memberBusy = null;
		}
	}

	async function reset() {
		if (!problem || !canReset) return;
		const confirmed = await confirmAction({
			title: 'Start new encryption keys?',
			description:
				'Clips synced before now stay unreadable on this device, and on every device that doesn’t already have the old key. This can’t be undone.',
			confirmLabel: 'Start new keys',
			tone: 'danger',
		});
		if (!confirmed) return;
		resetting = true;
		try {
			const version = await resetEncryption(problem.server_version);
			toast.success('Started new encryption keys', `Key ${version} is active. Syncing again.`);
			await resume();
		} catch (e) {
			toast.error('Encryption was not reset', errorMessage(e));
			await load();
		} finally {
			resetting = false;
		}
	}

	function title(backup: KeyBackup): string {
		return backup.created_at ? `Set aside ${formatRelative(backup.created_at).toLowerCase()}` : backup.name;
	}
</script>

{#snippet backupRow(backup: KeyBackup)}
	{@const fixes = holdsMissingKey(backup, problem)}
	<li class="flex items-center gap-3 px-3.5 py-3">
		<div class="min-w-0 flex-1">
			<p class="flex flex-wrap items-center gap-x-2 gap-y-1 text-[13px] font-medium text-fg">
				<span class="truncate">{title(backup)}</span>
				{#if fixes && problem}<Badge tone="success">Has key {problem.server_version}</Badge>{/if}
				{#if backup.same_account === false}<Badge tone="danger">Another account</Badge>{/if}
			</p>
			<p class="mt-0.5 text-xs break-all text-muted" title={backup.path}>
				{#if backup.problem}{backup.problem}{:else}{describeVersions(backup.versions)} · {backup.path}{/if}
			</p>
		</div>
		<Button
			size="sm"
			variant={fixes ? 'primary' : 'secondary'}
			disabled={!isRestorable(backup) || busy}
			loading={busyPath === backup.path}
			onclick={() => restore(backup)}
		>
			Restore
		</Button>
	</li>
{/snippet}

{#snippet memberRow(device: KeyMember)}
	<li class="px-3.5 py-3">
		<div class="flex items-center gap-3">
			<div class="min-w-0 flex-1">
				<p class="flex flex-wrap items-center gap-x-2 gap-y-1 text-[13px] font-medium text-fg">
					<span class="truncate">{device.name}</span>
					{#if !device.can_receive_keys}
						<Badge tone="danger">Needs an update</Badge>
					{:else if device.verified}
						<Badge tone="success">Verified</Badge>
					{:else}
						<Badge tone="warning">Not verified here</Badge>
					{/if}
				</p>
				{#if !device.can_receive_keys}
					<p class="mt-0.5 text-xs text-muted">It runs a cpmesh too old to receive keys: update it, or remove it.</p>
				{/if}
			</div>
			{#if device.can_receive_keys && !device.verified && verifyingId !== device.id}
				<Button size="sm" icon="fingerprint" disabled={busy} onclick={() => startVerifying(device)}>Verify</Button>
			{/if}
			<Button size="sm" variant="ghost" disabled={busy} loading={memberBusy === device.id && verifyingId !== device.id} onclick={() => remove(device)}>
				Remove
			</Button>
		</div>
		{#if verifyingId === device.id}
			<form class="mt-3 flex flex-col gap-2.5" onsubmit={(event) => verify(event, device)} novalidate>
				<Field
					label="Its full fingerprint"
					hint="Read it on {device.name} itself, under Devices → This device’s fingerprint, and type all 64 characters. Spaces are ignored."
					inputClass="font-mono tracking-wider uppercase"
					autocomplete="off"
					spellcheck={false}
					autocapitalize="characters"
					bind:value={peerFingerprint}
					error={verifyError}
				/>
				<div class="flex justify-end gap-2">
					<Button size="sm" variant="ghost" disabled={memberBusy !== null} onclick={() => (verifyingId = null)}>Cancel</Button>
					<Button type="submit" size="sm" variant="primary" loading={memberBusy === device.id} disabled={!peerFingerprint.trim()}>
						Verify identity
					</Button>
				</div>
			</form>
		{/if}
	</li>
{/snippet}

<Dialog
	bind:open={recovery.dialogOpen}
	locked={busy}
	title="Encryption keys"
	description={problem
		? 'This device doesn’t have your account’s current encryption key, so it can’t sync.'
		: 'Restore keys from a backup to read clips synced before this device had them.'}
>
	{#if loadError}
		<Alert tone="danger" title="Couldn’t check the keys">
			{loadError}
			{#snippet actions()}
				<Button size="sm" icon="refresh" onclick={load}>Try again</Button>
			{/snippet}
		</Alert>
	{:else if !status}
		<div class="space-y-2" aria-busy="true" aria-label="Checking keys">
			<Skeleton class="h-3 w-2/3" />
			<Skeleton class="h-16 w-full rounded-lg" />
		</div>
	{:else}
		<p class="text-xs text-muted">
			This device has {describeVersions(status.versions)}{problem ? `; your account is on key ${problem.server_version}` : ''}.
		</p>

		{#if problem && status.devices.length > 0}
			<h3 class="mt-4 mb-1 text-[13px] font-semibold text-fg">Get it from another device</h3>
			<p class="mb-3 text-xs leading-relaxed text-muted">
				If {listNames(status.devices.map((d) => d.name))} still {status.devices.length === 1 ? 'has' : 'have'} your key, verify
				this device there: open Devices, choose Verify a device, pick “{thisDevice}” and enter this fingerprint. A device that has
				the key then shares it with this one.
			</p>
			{#if ownFingerprint}
				<Fingerprint value={ownFingerprint} label="This device’s fingerprint" />
			{:else}
				<Skeleton class="h-[92px] w-full rounded-lg" />
			{/if}
		{/if}

		<h3 class="mt-5 mb-2 text-[13px] font-semibold text-fg">Restore from a backup</h3>
		{#if backups.length === 0}
			<p class="text-xs leading-relaxed text-muted">
				No backups on this computer. cpmesh makes one whenever it sets keys aside; you can also choose a folder below.
			</p>
		{:else}
			<ul class="divide-y divide-border overflow-hidden rounded-lg border border-border">
				{#each backups as backup (backup.path)}
					{@render backupRow(backup)}
				{/each}
			</ul>
		{/if}

		<form class="mt-3 flex items-start gap-2" onsubmit={checkFolder} novalidate>
			<Field
				class="flex-1"
				label="Another folder"
				placeholder="/path/to/backup"
				hint="A folder with keyring.enc, and the device.key that was next to it, if there was one."
				autocomplete="off"
				spellcheck={false}
				bind:value={otherFolder}
			/>
			<Button type="submit" class="mt-[26px]" loading={checking} disabled={!otherFolder.trim() || busy}>Check</Button>
		</form>
		{#if checkedFolder}
			<ul class="mt-2 overflow-hidden rounded-lg border border-border">
				{@render backupRow(checkedFolder)}
			</ul>
		{/if}

		{#if problem}
			<h3 class="mt-6 mb-2 text-[13px] font-semibold text-danger-fg">Start new encryption keys</h3>
			<Alert tone="danger" title="Only if no device and no backup has your current key">
				A new key lets your devices sync again, but clips synced so far stay unreadable on this device, and on every device
				that doesn’t already have the old key. If you find a backup later, you can still restore it to read them.
			</Alert>
			{#if status.devices_error}
				<Alert tone="warning" class="mt-3" title="Couldn’t list your other devices">
					{status.devices_error}
					{#snippet actions()}
						<Button size="sm" icon="refresh" onclick={load}>Try again</Button>
					{/snippet}
				</Alert>
			{:else if status.devices.length > 0}
				<p class="mt-3 mb-2 text-xs leading-relaxed text-muted">
					Every approved device gets the new key, so each one has to be verified on this device first, or removed.
				</p>
				<ul class="divide-y divide-border overflow-hidden rounded-lg border border-border">
					{#each status.devices as device (device.id)}
						{@render memberRow(device)}
					{/each}
				</ul>
			{/if}
			<label class="mt-3 flex items-start gap-2.5 text-[13px] leading-snug text-fg">
				<input type="checkbox" class="mt-0.5 accent-[var(--color-danger)]" bind:checked={understood} disabled={busy} />
				I understand that clips synced before now can’t be read on this device
			</label>
		{/if}
	{/if}

	{#snippet footer()}
		<Button variant="ghost" disabled={busy} onclick={() => (recovery.dialogOpen = false)}>Close</Button>
		{#if problem && status}
			<Button variant="danger" loading={resetting} disabled={!canReset || busy} onclick={reset}>Start new encryption keys</Button>
		{/if}
	{/snippet}
</Dialog>
