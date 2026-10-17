<script lang="ts">
	import { removeDevice, verifyDeviceIdentity, type KeyMember } from '#lib/api.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import { errorMessage } from '#lib/ui.js';
	import Badge from './ui/Badge.svelte';
	import Button from './ui/Button.svelte';
	import Field from './ui/Field.svelte';

	/**
	 * Approved devices with what a new encryption key needs from each, and a way to give it
	 * right here: verify a device (full fingerprint), remove it, or, where offered, share the
	 * key with it (pairing code). Used by the Encryption keys dialog, the Devices page and
	 * the approval dialog.
	 */
	interface Props {
		devices: KeyMember[];
		/** After a device was verified or removed */
		onchanged: () => unknown;
		/** Set while verifying or removing, so the surrounding screen can wait */
		busy?: boolean;
		disabled?: boolean;
		/** Offers Share key for devices this returns true for */
		canShare?: (device: KeyMember) => boolean;
		onshare?: (device: KeyMember) => void;
	}

	let { devices, onchanged, busy = $bindable(false), disabled = false, canShare, onshare }: Props = $props();

	let verifyingId = $state<string | null>(null);
	let fingerprint = $state('');
	let verifyError = $state('');
	let busyId = $state<string | null>(null);

	$effect(() => {
		busy = busyId !== null;
	});

	function startVerifying(device: KeyMember) {
		verifyingId = device.id;
		fingerprint = '';
		verifyError = '';
	}

	async function verify(event: SubmitEvent, device: KeyMember) {
		event.preventDefault();
		busyId = device.id;
		verifyError = '';
		try {
			const update = await verifyDeviceIdentity(device.id, fingerprint);
			toast.success(`${device.name} verified`, update.shared ? 'It received your encryption key.' : undefined);
			verifyingId = null;
			await onchanged();
		} catch (e) {
			verifyError = errorMessage(e);
		} finally {
			busyId = null;
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
		busyId = device.id;
		try {
			// The new key may wait for other devices in this list; the list shows which
			await removeDevice(device.id);
			toast.success(`${device.name} removed`);
			await onchanged();
		} catch (e) {
			toast.error('Couldn’t remove the device', errorMessage(e));
		} finally {
			busyId = null;
		}
	}
</script>

<ul class="divide-y divide-border overflow-hidden rounded-lg border border-border bg-surface">
	{#each devices as device (device.id)}
		{@const sharing = canShare?.(device) && onshare}
		<li class="px-3.5 py-3">
			<div class="flex items-center gap-3 max-sm:flex-wrap">
				<div class="min-w-0 flex-1">
					<p class="flex flex-wrap items-center gap-x-2 gap-y-1 text-[13px] font-medium text-fg">
						<span class="truncate">{device.name}</span>
						{#if device.trust === 'key_changed'}
							<Badge tone="danger">Identity changed</Badge>
						{:else if device.trust === 'revoked'}
							<Badge tone="danger">Removed earlier</Badge>
						{:else if !device.can_receive_keys}
							<Badge tone="danger">Needs an update</Badge>
						{:else if device.verified}
							<Badge tone="success">Verified</Badge>
						{:else}
							<Badge tone="warning">Not verified here</Badge>
						{/if}
						{#if sharing}<Badge tone="warning">Needs the key</Badge>{/if}
					</p>
					{#if device.trust === 'key_changed'}
						<p class="mt-0.5 text-xs text-muted">Its identity changed since you verified it. Remove it; it can rejoin through approval.</p>
					{:else if device.trust === 'revoked'}
						<p class="mt-0.5 text-xs text-muted">You removed it earlier, so it can’t receive keys again. Remove it.</p>
					{:else if !device.can_receive_keys}
						<p class="mt-0.5 text-xs text-muted">It runs a cpmesh too old to receive keys: update it, or remove it.</p>
					{:else if sharing}
						<p class="mt-0.5 text-xs text-muted">Share the key to verify it with a pairing code and hand it the key at once.</p>
					{/if}
				</div>
				<div class="flex shrink-0 items-center gap-1.5">
					{#if sharing}
						<Button size="sm" icon="key" disabled={disabled || busy} onclick={() => onshare?.(device)}>Share key</Button>
					{:else if device.trust === 'unverified' && device.can_receive_keys && verifyingId !== device.id}
						<Button size="sm" icon="fingerprint" disabled={disabled || busy} onclick={() => startVerifying(device)}>Verify</Button>
					{/if}
					<Button
						size="sm"
						variant="ghost"
						disabled={disabled || busy}
						loading={busyId === device.id && verifyingId !== device.id}
						onclick={() => remove(device)}
					>
						Remove
					</Button>
				</div>
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
						bind:value={fingerprint}
						error={verifyError}
					/>
					<div class="flex justify-end gap-2">
						<Button size="sm" variant="ghost" disabled={busyId !== null} onclick={() => (verifyingId = null)}>Cancel</Button>
						<Button type="submit" size="sm" variant="primary" loading={busyId === device.id} disabled={!fingerprint.trim()}>
							Verify identity
						</Button>
					</div>
				</form>
			{/if}
		</li>
	{/each}
</ul>
