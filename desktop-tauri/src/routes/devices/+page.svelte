<script lang="ts">
	import { onMount } from 'svelte';
	import { listen, type UnlistenFn } from '@tauri-apps/api/event';
	import {
		getDevices,
		removeDevice,
		getPendingDevices,
		beginDeviceApproval,
		confirmDeviceApproval,
		rejectPendingDevice,
		getOwnIdentity,
		verifyDeviceIdentity,
		type DeviceInfo,
		type PendingDevice,
		type ApprovalSession,
	} from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { setPendingDeviceCount } from '#lib/store.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import { deviceIcon, errorMessage, formatRelative } from '#lib/ui.js';
	import Alert from '#lib/components/ui/Alert.svelte';
	import Badge from '#lib/components/ui/Badge.svelte';
	import Button from '#lib/components/ui/Button.svelte';
	import Dialog from '#lib/components/ui/Dialog.svelte';
	import EmptyState from '#lib/components/ui/EmptyState.svelte';
	import Field from '#lib/components/ui/Field.svelte';
	import Fingerprint from '#lib/components/ui/Fingerprint.svelte';
	import Icon from '#lib/components/ui/Icon.svelte';
	import PageHeader from '#lib/components/ui/PageHeader.svelte';
	import Skeleton from '#lib/components/ui/Skeleton.svelte';

	let devices = $state<DeviceInfo[]>([]);
	let pendingDevices = $state<PendingDevice[]>([]);
	let loading = $state(true);
	let error = $state('');
	let removingId = $state<string | null>(null);
	let rejectingId = $state<string | null>(null);

	// Approval dialog
	let approvalOpen = $state(false);
	let approvalSession = $state<ApprovalSession | null>(null);
	let approvingDevice = $state<PendingDevice | null>(null);
	let confirming = $state(false);
	let approvalError = $state('');

	// Identity and peer verification
	let ownDeviceId = $state('');
	let ownFingerprint = $state('');
	let identityError = $state('');
	let verifyOpen = $state(false);
	let verifyingDevice = $state('');
	let expectedFingerprint = $state('');
	let verifyError = $state('');
	let verifying = $state(false);

	const verifiableDevices = $derived(devices.filter((d) => d.id !== ownDeviceId));

	function friendlyError(raw: unknown): string {
		const s = errorMessage(raw);
		if (s.includes('version conflict')) return 'Another device updated the encryption keys at the same time. Please try again.';
		if (s.includes('Encryption not initialized')) return 'Encryption is not ready. Try restarting the app.';
		if (s.includes('no active approval session') || s.includes('Session expired')) return 'The approval session expired. Please start over.';
		if (s.includes('session_id mismatch')) return 'The approval session has changed. Please start over.';
		if (s.includes('not the approver')) return 'Only the device that started approval can confirm it.';
		return s;
	}

	async function loadDevices() {
		error = '';
		try {
			const [devs, pending] = await Promise.all([getDevices(), getPendingDevices()]);
			// Pending, rejected and revoked devices are not part of the main list
			const pendingIds = new Set(pending.map((d) => d.id));
			devices = devs
				.filter((d) => d.status === 'approved' && !pendingIds.has(d.id))
				.sort((a, b) => Number(b.id === ownDeviceId) - Number(a.id === ownDeviceId) || Number(b.online) - Number(a.online));
			pendingDevices = pending;
			setPendingDeviceCount(pending.length);
		} catch (e) {
			error = errorMessage(e);
		} finally {
			loading = false;
		}
	}

	async function handleRemove(device: DeviceInfo) {
		const confirmed = await confirmAction({
			title: `Remove “${device.name}”?`,
			description: 'It stops receiving clips right away and has to be approved again to rejoin.',
			confirmLabel: 'Remove device',
			tone: 'danger',
		});
		if (!confirmed) return;
		removingId = device.id;
		try {
			await removeDevice(device.id);
			devices = devices.filter((d) => d.id !== device.id);
			toast.success(`${device.name} removed`);
		} catch (e) {
			toast.error('Couldn’t remove the device', errorMessage(e));
		} finally {
			removingId = null;
		}
	}

	async function handleBeginApproval(device: PendingDevice) {
		approvalError = '';
		approvalSession = null;
		approvingDevice = device;
		approvalOpen = true;
		try {
			approvalSession = await beginDeviceApproval(device.id);
		} catch (e) {
			approvalError = friendlyError(e);
		}
	}

	async function handleConfirmApproval() {
		if (!approvingDevice || !approvalSession || confirming) return;
		approvalError = '';
		confirming = true;
		try {
			await confirmDeviceApproval(approvingDevice.id, approvalSession.session_id, approvalSession.approval_code);
			const name = approvingDevice.name;
			confirming = false;
			approvalOpen = false;
			toast.success(`${name} approved`, 'It can now send and receive clips.');
			await loadDevices();
		} catch (e) {
			approvalError = friendlyError(e);
		} finally {
			confirming = false;
		}
	}

	function onApprovalClosed() {
		approvalSession = null;
		approvingDevice = null;
		approvalError = '';
	}

	async function handleReject(device: PendingDevice) {
		const confirmed = await confirmAction({
			title: `Reject “${device.name}”?`,
			description: 'It won’t be able to read your clipboard. It can ask again by signing in again.',
			confirmLabel: 'Reject',
			tone: 'danger',
		});
		if (!confirmed) return;
		rejectingId = device.id;
		try {
			await rejectPendingDevice(device.id);
			pendingDevices = pendingDevices.filter((d) => d.id !== device.id);
			setPendingDeviceCount(pendingDevices.length);
		} catch (e) {
			toast.error('Couldn’t reject the device', errorMessage(e));
		} finally {
			rejectingId = null;
		}
	}

	async function verifyExistingDevice(event: SubmitEvent) {
		event.preventDefault();
		verifying = true;
		verifyError = '';
		try {
			await verifyDeviceIdentity(verifyingDevice, expectedFingerprint);
			const name = devices.find((d) => d.id === verifyingDevice)?.name ?? 'Device';
			toast.success(`${name} verified`, 'Reconnect to synchronise the authenticated keys.');
			expectedFingerprint = '';
			verifyingDevice = '';
			verifyOpen = false;
		} catch (e) {
			verifyError = errorMessage(e);
		} finally {
			verifying = false;
		}
	}

	onMount(() => {
		getOwnIdentity()
			.then((identity) => {
				ownDeviceId = identity.device_id;
				ownFingerprint = identity.fingerprint;
			})
			.catch((e) => {
				identityError = errorMessage(e);
			})
			.finally(loadDevices);
		let unlisten: UnlistenFn | undefined;
		let disposed = false;
		listen('device-status-changed', () => loadDevices()).then((u) => {
			if (disposed) u();
			else unlisten = u;
		});
		return () => {
			disposed = true;
			unlisten?.();
		};
	});
</script>

<svelte:head>
	<title>Devices · cpmesh</title>
</svelte:head>

<PageHeader title="Devices" description="Every device here holds your encryption key. Approve new ones only after comparing fingerprints." />

{#if error}
	<Alert tone="danger" class="mb-6" title="Couldn’t load devices" ondismiss={() => (error = '')}>
		{error}
		{#snippet actions()}
			<Button size="sm" icon="refresh" onclick={loadDevices}>Try again</Button>
		{/snippet}
	</Alert>
{/if}

{#if pendingDevices.length > 0}
	<section class="mb-8" aria-labelledby="pending-heading">
		<h2 id="pending-heading" class="mb-2 flex items-center gap-2 px-1 text-[13px] font-semibold text-fg">
			<span class="status-dot text-accent" data-live="true"></span>
			Waiting for approval
		</h2>
		<ul class="divide-y divide-border overflow-hidden rounded-xl border border-border-strong bg-surface shadow-sm">
			{#each pendingDevices as device (device.id)}
				<li class="flex items-center gap-3 px-4 py-3.5 max-sm:flex-wrap">
					<span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border bg-bg-deep text-muted">
						<Icon name={deviceIcon(device.name)} size={17} strokeWidth={1.75} />
					</span>
					<div class="min-w-0 flex-1">
						<p class="truncate text-[13px] font-medium text-fg">{device.name}</p>
						<p class="text-xs text-muted">Asked to join {formatRelative(device.created_at).toLowerCase()}</p>
					</div>
					<div class="flex shrink-0 items-center gap-2">
						<Button size="sm" variant="ghost" loading={rejectingId === device.id} onclick={() => handleReject(device)}>Reject</Button>
						<Button size="sm" variant="primary" icon="shield-check" disabled={approvalOpen} onclick={() => handleBeginApproval(device)}>
							Review and approve
						</Button>
					</div>
				</li>
			{/each}
		</ul>
	</section>
{/if}

<section aria-labelledby="devices-heading">
	<h2 id="devices-heading" class="mb-2 px-1 text-[13px] font-semibold text-fg">
		Your devices
		{#if !loading && devices.length > 0}<span class="ml-1 font-normal text-dim tabular-nums">{devices.length}</span>{/if}
	</h2>

	{#if loading}
		<div class="divide-y divide-border rounded-xl border border-border" aria-busy="true" aria-label="Loading devices">
			{#each [0, 1, 2] as i (i)}
				<div class="flex items-center gap-3 px-4 py-3.5">
					<Skeleton class="h-9 w-9 rounded-lg" />
					<div class="flex-1 space-y-2">
						<Skeleton class="h-3.5 w-1/3" />
						<Skeleton class="h-3 w-1/5" />
					</div>
				</div>
			{/each}
		</div>
	{:else if devices.length === 0}
		<div class="rounded-xl border border-dashed border-border-strong">
			<EmptyState
				icon="monitor"
				title="No approved devices yet"
				description="Install cpmesh on another computer or phone and sign in. It appears above, waiting for your approval."
			/>
		</div>
	{:else}
		<ul class="divide-y divide-border overflow-hidden rounded-xl border border-border bg-surface">
			{#each devices as device (device.id)}
				{@const self = device.id === ownDeviceId}
				<li class="flex items-center gap-3 px-4 py-3.5">
					<span
						class="relative flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border bg-bg-deep {self ? 'border-ink text-fg' : 'border-border text-muted'}"
					>
						<Icon name={deviceIcon(device.name)} size={17} strokeWidth={1.75} />
						<span
							class="absolute -right-0.5 -bottom-0.5 h-2.5 w-2.5 rounded-full border-2 border-surface {device.online ? 'bg-success' : 'bg-border-strong'}"
							aria-hidden="true"
						></span>
					</span>
					<div class="min-w-0 flex-1">
						<p class="flex items-center gap-2 text-[13px] font-medium text-fg">
							<span class="truncate">{device.name}</span>
							{#if self}<Badge tone="ink">This device</Badge>{/if}
						</p>
						<p class="text-xs text-muted">
							{#if device.online}<span class="text-success-fg">Online</span>{:else}Last seen {formatRelative(device.last_seen).toLowerCase()}{/if}
						</p>
					</div>
					{#if !self}
						<Button
							size="icon-sm"
							variant="ghost"
							icon="trash"
							class="hover:bg-danger-soft hover:text-danger"
							aria-label="Remove {device.name}"
							title="Remove device"
							loading={removingId === device.id}
							onclick={() => handleRemove(device)}
						/>
					{/if}
				</li>
			{/each}
		</ul>
	{/if}
</section>

<section class="mt-10" aria-labelledby="identity-heading">
	<h2 id="identity-heading" class="px-1 text-[13px] font-semibold text-fg">This device’s fingerprint</h2>
	<p class="mt-0.5 mb-3 px-1 text-xs leading-relaxed text-muted">
		Read it from this screen when another device asks you to compare. After an update, verify peers you already trust the
		same way — always read the other fingerprint on the other device itself, never from a list the relay sends.
	</p>

	<div class="rounded-xl border border-border bg-surface p-4">
		{#if ownFingerprint}
			<Fingerprint value={ownFingerprint} label="This device's fingerprint" />
		{:else if identityError}
			<Alert tone="danger">{identityError}</Alert>
		{:else}
			<Skeleton class="h-[92px] w-full rounded-lg" />
		{/if}

		{#if !verifyOpen}
			<div class="mt-4 flex items-center justify-between gap-4">
				<p class="text-xs text-muted">Need to re-establish trust with a device after an update?</p>
				<Button size="sm" icon="fingerprint" disabled={verifiableDevices.length === 0} onclick={() => (verifyOpen = true)}>
					Verify a device
				</Button>
			</div>
		{:else}
			<form class="mt-4 flex flex-col gap-3.5 border-t border-border pt-4" onsubmit={verifyExistingDevice} novalidate>
				<div class="flex flex-col gap-1.5">
					<label for="verify-device" class="text-[13px] font-medium text-fg">Device to verify</label>
					<select
						id="verify-device"
						bind:value={verifyingDevice}
						class="h-9 w-full rounded-md border border-border bg-surface px-3 text-[13px] text-fg shadow-xs outline-none hover:border-border-strong focus:border-ink"
					>
						<option value="" disabled>Choose a device</option>
						{#each verifiableDevices as device (device.id)}
							<option value={device.id}>{device.name}</option>
						{/each}
					</select>
				</div>
				<Field
					label="Its full fingerprint"
					hint="Type or paste all 64 characters exactly as the other device shows them. Spaces are ignored."
					inputClass="font-mono tracking-wider uppercase"
					autocomplete="off"
					spellcheck={false}
					autocapitalize="characters"
					bind:value={expectedFingerprint}
					error={verifyError}
				/>
				<div class="flex justify-end gap-2">
					<Button
						variant="ghost"
						size="sm"
						onclick={() => {
							verifyOpen = false;
							verifyError = '';
						}}>Cancel</Button
					>
					<Button type="submit" variant="primary" size="sm" loading={verifying} disabled={!verifyingDevice || !expectedFingerprint.trim()}>
						Verify identity
					</Button>
				</div>
			</form>
		{/if}
	</div>
</section>

<Dialog
	bind:open={approvalOpen}
	locked={confirming}
	title={approvingDevice ? `Approve “${approvingDevice.name}”` : 'Approve device'}
	description="Compare every group with the fingerprint on the new device, or over a channel you trust. Both devices must confirm."
	onclose={onApprovalClosed}
>
	{#if approvalSession}
		<Fingerprint value={approvalSession.approval_code} label="Pairing fingerprint" />
		<p class="mt-3 flex items-start gap-2 text-xs leading-relaxed text-muted">
			<Icon name="alert-triangle" size={13} class="mt-0.5 text-warning" />
			If even one character differs, don’t approve: someone may be impersonating your device.
		</p>
	{:else if !approvalError}
		<div class="space-y-2" aria-busy="true" aria-label="Starting approval">
			<Skeleton class="h-[92px] w-full rounded-lg" />
			<Skeleton class="h-3 w-2/3" />
		</div>
	{/if}
	{#if approvalError}
		<Alert tone="danger" class="mt-3">{approvalError}</Alert>
	{/if}
	{#snippet footer()}
		<Button variant="ghost" disabled={confirming} onclick={() => (approvalOpen = false)}>Cancel</Button>
		{#if approvalSession}
			<Button variant="primary" icon="check" loading={confirming} onclick={handleConfirmApproval}>Every group matches — approve</Button>
		{/if}
	{/snippet}
</Dialog>
