<script lang="ts">
	import { onMount, tick } from 'svelte';
	import { listen, type UnlistenFn } from '@tauri-apps/api/event';
	import {
		getDevices,
		removeDevice,
		getPendingDevices,
		beginDeviceApproval,
		pollDeviceApproval,
		confirmDeviceApproval,
		confirmKeyShare,
		rejectPendingDevice,
		getOwnIdentity,
		getDeviceTrust,
		verifyDeviceIdentity,
		type DeviceInfo,
		type KeyMember,
		type PendingDevice,
		type ApprovalSession,
	} from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { setPendingDeviceCount } from '#lib/store.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import { openKeyRecovery, recovery, resetBlockers } from '#lib/recovery.svelte.js';
	import { canShareKeyWith, trustBadge } from '#lib/trust.js';
	import { deviceIcon, errorMessage, formatRelative } from '#lib/ui.js';
	import KeyMembers from '#lib/components/KeyMembers.svelte';
	import Alert from '#lib/components/ui/Alert.svelte';
	import Badge from '#lib/components/ui/Badge.svelte';
	import Button from '#lib/components/ui/Button.svelte';
	import Dialog from '#lib/components/ui/Dialog.svelte';
	import EmptyState from '#lib/components/ui/EmptyState.svelte';
	import Field from '#lib/components/ui/Field.svelte';
	import Fingerprint from '#lib/components/ui/Fingerprint.svelte';
	import PairingCode from '#lib/components/ui/PairingCode.svelte';
	import Icon from '#lib/components/ui/Icon.svelte';
	import PageHeader from '#lib/components/ui/PageHeader.svelte';
	import Skeleton from '#lib/components/ui/Skeleton.svelte';

	let devices = $state<DeviceInfo[]>([]);
	let pendingDevices = $state<PendingDevice[]>([]);
	let loading = $state(true);
	let error = $state('');
	let removingId = $state<string | null>(null);
	let rejectingId = $state<string | null>(null);

	// How this device trusts each other approved device, and who has the current key
	let trust = $state<KeyMember[]>([]);

	// Pairing dialog: approving a pending device, or sharing the key with an approved one
	let approvalOpen = $state(false);
	let approvalSession = $state<ApprovalSession | null>(null);
	let approvingDevice = $state<{ id: string; name: string } | null>(null);
	let pairingMode = $state<'approve' | 'share'>('approve');
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
	const trustById = $derived(new Map(trust.map((member) => [member.id, member])));
	const ownLacksKey = $derived(
		recovery.keyProblem !== null || devices.find((d) => d.id === ownDeviceId)?.has_current_key === false,
	);
	// A device without the key can neither share it nor approve; it gets the key first.
	const blockers = $derived(ownLacksKey ? [] : resetBlockers(trust));
	// Pairing verifies the device being shared with, so it doesn't stand in its own way
	const dialogBlockers = $derived(approvingDevice ? blockers.filter((d) => d.id !== approvingDevice?.id) : []);
	const canShare = (member: KeyMember) => canShareKeyWith(member, ownLacksKey);

	// Once the key arrives (or is restored), the relay lists this device with it too
	let hadKeyProblem = false;
	$effect(() => {
		const missing = recovery.keyProblem !== null;
		if (hadKeyProblem && !missing) loadDevices();
		hadKeyProblem = missing;
	});

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
			const [devs, pending] = await Promise.all([getDevices(), getPendingDevices(), loadTrust()]);
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

	// Without it (e.g. an older server) the page still lists devices, just without
	// verification and key status.
	async function loadTrust() {
		try {
			trust = await getDeviceTrust();
		} catch {
			trust = [];
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
			const update = await removeDevice(device.id);
			devices = devices.filter((d) => d.id !== device.id);
			if (update.blocked) {
				toast.warning(
					`${device.name} removed`,
					`Sending from this device is paused until the key changes. ${update.blocked}`,
					12000,
				);
			} else {
				toast.success(`${device.name} removed`);
			}
		} catch (e) {
			toast.error('Couldn’t remove the device', errorMessage(e));
		} finally {
			removingId = null;
			loadTrust();
		}
	}

	let sasPollTimer: ReturnType<typeof setInterval> | null = null;

	function stopSasPolling() {
		if (sasPollTimer) {
			clearInterval(sasPollTimer);
			sasPollTimer = null;
		}
	}

	// The 8-digit code exists only after the other device contributed its nonce and
	// we opened our commitment; poll until then.
	async function pollSas() {
		if (!approvingDevice || !approvalSession) return;
		try {
			const updated = await pollDeviceApproval(approvingDevice.id, approvalSession.session_id);
			approvalSession = updated;
			if (updated.sas) stopSasPolling();
		} catch (e) {
			approvalError = friendlyError(e);
			stopSasPolling();
		}
	}

	async function startPairing(target: { id: string; name: string }, mode: 'approve' | 'share') {
		approvalError = '';
		approvalSession = null;
		approvingDevice = { id: target.id, name: target.name };
		pairingMode = mode;
		approvalOpen = true;
		loadTrust();
		try {
			approvalSession = await beginDeviceApproval(target.id);
			stopSasPolling();
			sasPollTimer = setInterval(pollSas, 1500);
		} catch (e) {
			approvalError = friendlyError(e);
		}
	}

	function handleBeginApproval(device: PendingDevice) {
		startPairing(device, 'approve');
	}

	// The other device trusts this one by the same code, then the key reaches it.
	function handleShareKey(device: DeviceInfo) {
		startPairing(device, 'share');
	}

	async function handleConfirmPairing() {
		if (!approvingDevice || !approvalSession?.sas || confirming) return;
		approvalError = '';
		confirming = true;
		const { id, name } = approvingDevice;
		try {
			if (pairingMode === 'approve') {
				await confirmDeviceApproval(id, approvalSession.session_id, approvalSession.sas);
				toast.success(`${name} approved`, 'It can now send and receive clips.');
			} else {
				await confirmKeyShare(id, approvalSession.session_id, approvalSession.sas);
				toast.success(`Key shared with ${name}`, 'It syncs again once it connects.');
			}
			confirming = false;
			approvalOpen = false;
			await loadDevices();
		} catch (e) {
			approvalError = friendlyError(e);
			// Shows which devices are in the way, if that's what failed
			await loadTrust();
		} finally {
			confirming = false;
		}
	}

	function onApprovalClosed() {
		stopSasPolling();
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

	async function openVerify(deviceId: string) {
		verifyingDevice = deviceId;
		expectedFingerprint = '';
		verifyError = '';
		verifyOpen = true;
		await tick();
		document.getElementById('verify-device')?.scrollIntoView({ behavior: 'smooth', block: 'center' });
	}

	async function verifyExistingDevice(event: SubmitEvent) {
		event.preventDefault();
		verifying = true;
		verifyError = '';
		try {
			const update = await verifyDeviceIdentity(verifyingDevice, expectedFingerprint);
			const name = devices.find((d) => d.id === verifyingDevice)?.name ?? 'Device';
			if (update.blocked) {
				toast.warning(`${name} verified`, update.blocked, 12000);
			} else if (update.shared) {
				toast.success(`${name} verified`, 'It received your encryption key.');
			} else {
				toast.success(`${name} verified`, 'This device now accepts its keys and clips.');
			}
			expectedFingerprint = '';
			verifyingDevice = '';
			verifyOpen = false;
			loadTrust();
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
			stopSasPolling();
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

{#if blockers.length > 0}
	<section class="mb-8" aria-labelledby="blockers-heading">
		<h2 id="blockers-heading" class="flex items-center gap-2 px-1 text-[13px] font-semibold text-fg">
			<Icon name="alert-triangle" size={14} class="text-warning" />
			{blockers.length === 1 ? 'Verify or remove this device' : 'Verify or remove these devices'}
		</h2>
		<p class="mt-0.5 mb-3 px-1 text-xs leading-relaxed text-muted">
			Approving a device, sharing the key and changing it all send a new key to every device, and this one only sends keys to
			devices it has verified. Until then those steps can’t finish.
		</p>
		<KeyMembers
			devices={blockers}
			onchanged={loadDevices}
			disabled={approvalOpen}
			{canShare}
			onshare={(member) => {
				const device = devices.find((d) => d.id === member.id);
				if (device) handleShareKey(device);
			}}
		/>
	</section>
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
						<Button
							size="sm"
							variant="primary"
							icon="shield-check"
							disabled={approvalOpen || ownLacksKey}
							title={ownLacksKey ? 'This device needs the encryption key first' : undefined}
							onclick={() => handleBeginApproval(device)}
						>
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
				{@const member = trustById.get(device.id)}
				{@const badge = trustBadge(member)}
				<li class="flex items-center gap-3 px-4 py-3.5 max-sm:flex-wrap">
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
							{#if self && ownLacksKey}
								<Badge tone="warning">Needs the key</Badge>
							{:else if badge}
								<Badge tone={badge.tone}>{badge.label}</Badge>
							{/if}
						</p>
						<p class="text-xs text-muted">
							{#if device.online}<span class="text-success-fg">Online</span>{:else}Last seen {formatRelative(device.last_seen).toLowerCase()}{/if}
						</p>
					</div>
					{#if self && ownLacksKey}
						<Button size="sm" icon="key" onclick={openKeyRecovery}>Get the key…</Button>
					{:else if !self}
						<div class="flex shrink-0 items-center gap-1.5">
							{#if member && canShare(member)}
								<Button size="sm" icon="key" disabled={approvalOpen} onclick={() => handleShareKey(device)}>Share key</Button>
							{:else if member?.trust === 'unverified' && member.can_receive_keys}
								<Button size="sm" variant="ghost" icon="fingerprint" onclick={() => openVerify(device.id)}>Verify</Button>
							{/if}
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
						</div>
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
	title={pairingMode === 'share'
		? `Share the key with “${approvingDevice?.name ?? 'device'}”`
		: approvingDevice
			? `Approve “${approvingDevice.name}”`
			: 'Approve device'}
	description={pairingMode === 'share'
		? `On “${approvingDevice?.name ?? 'it'}”, open Recover keys… (or Settings → Encryption keys): it shows an 8-digit pairing code too. Share only if both screens show the same code.`
		: 'The new device shows an 8-digit pairing code too. Approve only if both screens show the same code.'}
	onclose={onApprovalClosed}
>
	{#if dialogBlockers.length > 0}
		<div class="mb-4">
			<p class="text-[13px] font-medium text-fg">
				First, verify or remove {dialogBlockers.length === 1 ? 'this device' : 'these devices'}
			</p>
			<p class="mt-0.5 mb-2.5 text-xs leading-relaxed text-muted">
				{pairingMode === 'share' ? 'Sharing' : 'Approving'} sends a new key to every device, and this one only sends keys to devices
				it has verified.
			</p>
			<KeyMembers devices={dialogBlockers} onchanged={loadDevices} disabled={confirming} />
		</div>
	{/if}
	{#if approvalSession?.sas}
		<PairingCode code={approvalSession.sas} fullCode={approvalSession.approval_code} />
		<p class="mt-3 flex items-start gap-2 text-xs leading-relaxed text-muted">
			<Icon name="alert-triangle" size={13} class="mt-0.5 text-warning" />
			If even one digit differs, don’t {pairingMode === 'share' ? 'share' : 'approve'}: someone may be impersonating your device.
		</p>
	{:else if approvalSession}
		<p class="flex items-center gap-2.5 text-[13px] text-muted" role="status">
			<span class="status-dot text-accent" data-live="true"></span>
			{#if pairingMode === 'share'}
				Waiting for “{approvingDevice?.name}”. Open cpmesh on it and choose Recover keys… (or Settings → Encryption keys).
			{:else}
				Exchanging pairing codes with “{approvingDevice?.name}”. Keep its waiting screen open.
			{/if}
		</p>
	{:else if !approvalError}
		<div class="space-y-2" aria-busy="true" aria-label="Starting pairing">
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
			<Button
				variant="primary"
				icon={pairingMode === 'share' ? 'key' : 'check'}
				loading={confirming}
				disabled={!approvalSession.sas || dialogBlockers.length > 0}
				title={dialogBlockers.length > 0 ? 'Verify or remove the devices above first' : undefined}
				onclick={handleConfirmPairing}
			>
				{pairingMode === 'share' ? 'Both devices show this code — share the key' : 'Both devices show this code — approve'}
			</Button>
		{/if}
	{/snippet}
</Dialog>
