<script lang="ts">
	import type { MyApprovalStatus } from '#lib/api.js';
	import Alert from './ui/Alert.svelte';
	import Button from './ui/Button.svelte';
	import Fingerprint from './ui/Fingerprint.svelte';
	import Icon from './ui/Icon.svelte';
	import Logo from './ui/Logo.svelte';

	/** Shown while this device waits for approval, and when it was rejected. */
	interface Props {
		mode: 'pending' | 'rejected';
		approval: MyApprovalStatus | null;
		error: string;
		confirming: boolean;
		onconfirm: () => void;
		onretry: () => void;
		onlogout: () => void;
	}

	let { mode, approval, error, confirming, onconfirm, onretry, onlogout }: Props = $props();

	const steps = [
		'Open cpmesh on a device you already use',
		'Go to Devices and find this device under Waiting for approval',
		'Choose Approve and compare the fingerprint on both screens',
	];
</script>

<div class="flex min-h-dvh flex-col bg-bg-deep">
	<header class="flex items-center justify-between px-6 py-4">
		<Logo size={24} withText />
		<Button variant="ghost" size="sm" icon="log-out" onclick={onlogout}>
			{mode === 'rejected' ? 'Sign out' : 'Cancel and sign out'}
		</Button>
	</header>

	<main class="flex flex-1 items-start justify-center px-6 pt-4 pb-12 sm:items-center sm:pt-0">
		<div class="w-full max-w-[460px] animate-[rise-in_0.3s_var(--ease-out-expo)]">
			{#if mode === 'rejected'}
				<div class="mb-4 flex h-11 w-11 items-center justify-center rounded-xl border border-danger-line bg-danger-soft text-danger">
					<Icon name="x" size={20} />
				</div>
				<h1 class="text-xl font-semibold tracking-tight text-fg">This device was not approved</h1>
				<p class="mt-2 text-[13px] leading-relaxed text-muted">
					Another device on your account rejected it. Sign out, then sign in again to send a new request.
				</p>
				<Button variant="primary" class="mt-6" icon="log-out" onclick={onlogout}>Sign out</Button>
			{:else}
				<div class="mb-4 flex h-11 w-11 items-center justify-center rounded-xl border border-border bg-surface text-fg shadow-xs">
					<Icon name="shield-check" size={20} strokeWidth={1.75} />
				</div>
				<h1 class="text-xl font-semibold tracking-tight text-fg">Approve this device from another one</h1>
				<p class="mt-2 text-[13px] leading-relaxed text-muted">
					Your clipboard is end-to-end encrypted. A device you already trust has to let this one in before it can read
					anything.
				</p>

				{#if error}
					<Alert tone="danger" class="mt-6" title="Approval status unavailable">
						{error}
						{#snippet actions()}
							<Button size="sm" icon="refresh" onclick={onretry}>Try again</Button>
						{/snippet}
					</Alert>
				{:else if approval?.approval_code}
					<div class="mt-6 rounded-xl border border-border bg-surface p-5 shadow-xs">
						<p class="text-[13px] font-medium text-fg">Compare this fingerprint</p>
						<p class="mt-0.5 text-xs leading-relaxed text-muted">
							Check every group against the approving device's screen, or over a channel you trust. Both devices must
							confirm.
						</p>
						<Fingerprint class="mt-4" value={approval.approval_code} label="Pairing fingerprint" />
						{#if approval.locally_verified}
							<p class="mt-4 flex items-center gap-2 text-[13px] font-medium text-success-fg">
								<Icon name="check-circle" size={15} />
								Confirmed here. Waiting for the other device…
							</p>
						{:else}
							<Button variant="primary" class="mt-4 w-full" icon="check" loading={confirming} onclick={onconfirm}>
								Every group matches — trust the approver
							</Button>
						{/if}
					</div>
				{:else}
					<ol class="mt-6 space-y-3">
						{#each steps as step, i (i)}
							<li class="flex items-start gap-3 text-[13px] text-fg">
								<span
									class="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-border bg-surface text-xs font-medium text-muted tabular-nums"
									>{i + 1}</span
								>
								<span class="pt-0.5">{step}</span>
							</li>
						{/each}
					</ol>
					<p class="mt-6 flex items-center gap-2.5 text-[13px] text-muted" role="status">
						<span class="status-dot text-accent" data-live="true"></span>
						Waiting for approval — this screen updates by itself
					</p>
				{/if}

				<p class="mt-8 border-t border-border pt-4 text-xs leading-relaxed text-muted">
					Updated cpmesh on a device that was already approved?
					<a href="/devices" class="font-medium text-fg underline decoration-border-strong underline-offset-4 hover:decoration-fg"
						>Verify an existing device's fingerprint</a
					> to restore trust.
				</p>
			{/if}
		</div>
	</main>
</div>
