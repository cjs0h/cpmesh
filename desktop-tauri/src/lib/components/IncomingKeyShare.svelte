<script lang="ts">
	import { onMount } from 'svelte';
	import {
		confirmPairing,
		connectToServer,
		getKeyProblem,
		getMyApprovalStatus,
		syncHistory,
		type MyApprovalStatus,
	} from '#lib/api.js';
	import { getAppStateValue } from '#lib/store.svelte.js';
	import { errorMessage } from '#lib/ui.js';
	import Alert from './ui/Alert.svelte';
	import Button from './ui/Button.svelte';
	import Icon from './ui/Icon.svelte';
	import PairingCode from './ui/PairingCode.svelte';

	/**
	 * On a device without the current key: shows the pairing code once a device that has
	 * the key starts sharing it (Devices → Share key), lets the user trust that device, and
	 * then fetches the key it shares.
	 */
	interface Props {
		/** Names a device by ID */
		nameOf: (id: string) => string | undefined;
		/** The key arrived */
		onreceived: () => unknown;
		/** Set while another device is pairing with this one */
		active?: boolean;
	}

	let { nameOf, onreceived, active = $bindable(false) }: Props = $props();

	let approval = $state<MyApprovalStatus | null>(null);
	let error = $state('');
	let confirming = $state(false);
	let receiving = false;
	let lastAttempt = 0;

	const sharer = $derived((approval?.approver_id && nameOf(approval.approver_id)) || 'the other device');

	$effect(() => {
		active = Boolean(approval?.approval_code);
	});

	// Once a device that has the key is trusted here, the key can arrive any moment; until
	// then, an occasional sync notices a key shared after a fingerprint comparison
	async function receive(every: number) {
		if (receiving || Date.now() - lastAttempt < every) return;
		receiving = true;
		lastAttempt = Date.now();
		try {
			if (getAppStateValue() === 'connected') await syncHistory();
			else await connectToServer();
		} catch {
			// Not shared yet
		}
		try {
			if ((await getKeyProblem()) === null) await onreceived();
		} finally {
			receiving = false;
		}
	}

	async function poll() {
		try {
			approval = await getMyApprovalStatus();
			error = '';
			await receive(approval.locally_verified ? 5000 : 15000);
		} catch (e) {
			error = errorMessage(e);
		}
	}

	async function trustSharer() {
		if (!approval?.session_id || !approval.sas || confirming) return;
		confirming = true;
		try {
			await confirmPairing(approval.session_id, approval.sas);
			await poll();
		} catch (e) {
			error = errorMessage(e);
		} finally {
			confirming = false;
		}
	}

	onMount(() => {
		poll();
		const timer = setInterval(poll, 3000);
		return () => clearInterval(timer);
	});
</script>

{#if error}
	<Alert tone="danger" class="mb-3">{error}</Alert>
{/if}

{#if approval?.sas}
	<p class="text-[13px] font-medium text-fg">Compare this pairing code with “{sharer}”</p>
	<PairingCode class="mt-2" code={approval.sas} fullCode={approval.approval_code} />
	{#if approval.locally_verified}
		<p class="mt-3 flex items-center gap-2 text-[13px] font-medium text-success-fg" role="status">
			<Icon name="check-circle" size={15} />
			Confirmed here. Waiting for “{sharer}” to share the key…
		</p>
	{:else}
		<p class="mt-3 flex items-start gap-2 text-xs leading-relaxed text-muted">
			<Icon name="alert-triangle" size={13} class="mt-0.5 text-warning" />
			If even one digit differs, don’t confirm: someone may be impersonating your device.
		</p>
		<Button variant="primary" class="mt-3 w-full" icon="check" loading={confirming} onclick={trustSharer}>
			Both devices show this code — trust “{sharer}”
		</Button>
	{/if}
{:else if approval?.approval_code}
	<p class="flex items-center gap-2.5 text-[13px] text-muted" role="status">
		<span class="status-dot text-accent" data-live="true"></span>
		Exchanging pairing codes with “{sharer}”…
	</p>
{:else}
	<p class="flex items-center gap-2.5 text-[13px] text-muted" role="status">
		<span class="status-dot text-accent" data-live="true"></span>
		The code appears here as soon as the other device starts sharing
	</p>
{/if}
