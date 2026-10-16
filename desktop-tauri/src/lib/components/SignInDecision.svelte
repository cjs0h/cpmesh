<script lang="ts">
	import type { SignInAction, SignInDecision } from '#lib/api.js';
	import { listNames, replacementPlan } from '#lib/recovery.svelte.js';
	import { formatRelative, serverHost } from '#lib/ui.js';
	import Alert from './ui/Alert.svelte';
	import Button from './ui/Button.svelte';

	/**
	 * A sign-in that stopped because keys saved on this computer, or the account's
	 * registration of it, don't fit the account signing in. Nothing about keys is decided
	 * for the user: each choice here is explicit, and nothing is deleted.
	 */
	interface Props {
		decision: SignInDecision;
		busy: boolean;
		error: string;
		onresolve: (action: SignInAction) => void;
		oncancel: () => void;
	}

	let { decision, busy, error, onresolve, oncancel }: Props = $props();

	let chosen = $state<string | null>(null);
	const selectedId = $derived(
		decision.kind === 'replace_device' ? (chosen ?? decision.suggested_device_id) : null,
	);
	const plan = $derived(decision.kind === 'replace_device' ? replacementPlan(decision.devices, selectedId) : null);

	const setAsideNote =
		'cpmesh moves them, with this computer’s clipboard history, into a backup folder. Nothing is deleted: you can restore them later in Settings → Encryption keys.';

	function statusLabel(status: string): string {
		return status === 'approved' ? 'Approved' : status === 'pending' ? 'Waiting for approval' : status === 'rejected' ? 'Rejected' : status;
	}
</script>

{#snippet heading(title: string, description: string)}
	<div class="mb-5">
		<h1 class="text-xl font-semibold tracking-tight text-fg">{title}</h1>
		<p class="mt-1.5 text-[13px] leading-relaxed text-muted">{description}</p>
	</div>
{/snippet}

{#snippet setAside(primary: boolean)}
	<Button variant={primary ? 'primary' : 'secondary'} size="lg" class="w-full" loading={busy} onclick={() => onresolve({ action: 'set_aside_keys' })}>
		Set them aside and continue
	</Button>
	<p class="text-xs leading-relaxed text-muted">{setAsideNote}</p>
{/snippet}

<div class="animate-[rise-in_0.25s_var(--ease-out-expo)]">
	{#if decision.kind === 'unknown_keys'}
		{@render heading(
			'Keys from an earlier sign-in',
			decision.readable
				? `This computer has encryption keys saved by an earlier version of cpmesh, which didn’t record which account they’re for. Choose what happens to them before ${decision.account} continues.`
				: 'This computer has encryption keys saved by an earlier version of cpmesh, but its device key can’t open them any more, so they can only be set aside.',
		)}
		{#if decision.readable && decision.matching_device}
			<Alert tone="success" class="mb-5" title="They look like yours">
				They belong to “{decision.matching_device}”, a device on {decision.account}.
			</Alert>
		{:else if decision.readable}
			<Alert class="mb-5" title="None of your devices uses them">
				They’re probably from another account. Set them aside unless you know they’re yours.
			</Alert>
		{/if}
		<div class="flex flex-col gap-3">
			{#if decision.readable}
				<Button
					variant={decision.matching_device ? 'primary' : 'secondary'}
					size="lg"
					class="w-full"
					loading={busy}
					onclick={() => onresolve({ action: 'use_saved_keys' })}
				>
					Use them for {decision.account}
				</Button>
				<p class="-mt-1 text-xs leading-relaxed text-muted">
					Only if you used cpmesh on this computer with {decision.account} before.
				</p>
			{/if}
			{@render setAside(!decision.readable || !decision.matching_device)}
		</div>
	{:else if decision.kind === 'other_account_keys'}
		{@render heading(
			'Keys for another account',
			`This computer has encryption keys for a different account on ${serverHost(decision.owner_server)}. cpmesh never uses one account’s keys for another: it keeps them, with that account’s clipboard history, in an archive on this computer, and they come back when that account signs in here again.`,
		)}
		{#if decision.returning}
			<Alert tone="success" class="mb-5" title="Welcome back">
				The keys {decision.account} used on this computer before come back too.
			</Alert>
		{/if}
		<div class="flex flex-col gap-3">
			<Button variant="primary" size="lg" class="w-full" loading={busy} onclick={() => onresolve({ action: 'set_aside_keys' })}>
				Archive them and continue
			</Button>
		</div>
	{:else if decision.kind === 'unreadable_keys'}
		{@render heading(
			'Saved keys can’t be opened',
			`This computer has encryption keys for ${decision.account}, but its device key changed since they were saved, so it can’t open them. If you still have the old device key, you can restore them later.`,
		)}
		<div class="flex flex-col gap-3">{@render setAside(true)}</div>
	{:else if decision.kind === 'replace_device'}
		{@render heading(
			'This computer is already registered',
			plan
				? `${decision.account} has this computer as “${plan.old.name}”, with device keys it no longer has — they were reset or removed. To continue, replace that registration.`
				: `${decision.account} has this computer registered with device keys it no longer has — they were reset or removed. Choose its old registration to replace it.`,
		)}

		{#if !decision.suggested_device_id || chosen !== null}
			<fieldset class="mb-5 overflow-hidden rounded-xl border border-border bg-surface">
				<legend class="sr-only">This computer’s old registration</legend>
				{#each decision.devices as device (device.id)}
					<label class="flex cursor-pointer items-center gap-3 border-b border-border px-4 py-3 last:border-b-0 hover:bg-bg-deep">
						<input
							type="radio"
							name="old-registration"
							value={device.id}
							checked={selectedId === device.id}
							disabled={busy}
							onchange={() => (chosen = device.id)}
						/>
						<span class="min-w-0 flex-1">
							<span class="block truncate text-[13px] font-medium text-fg">{device.name}</span>
							<span class="block text-xs text-muted">
								{statusLabel(device.status)} · {device.online ? 'Online' : `Last seen ${formatRelative(device.last_seen ?? undefined).toLowerCase()}`}
							</span>
						</span>
					</label>
				{/each}
			</fieldset>
		{:else if plan}
			<div class="mb-5 flex items-center justify-between gap-3 rounded-lg border border-border bg-bg-deep px-3.5 py-2.5 text-[13px]">
				<span class="min-w-0 truncate"><span class="font-medium text-fg">{plan.old.name}</span>
					<span class="text-muted"> · {statusLabel(plan.old.status)}</span></span
				>
				<button
					type="button"
					class="shrink-0 text-xs font-medium text-muted underline decoration-border-strong underline-offset-4 hover:text-fg"
					disabled={busy}
					onclick={() => (chosen = plan?.old.id ?? null)}
				>
					Not this one?
				</button>
			</div>
		{/if}

		{#if plan}
			<div class="mb-5 flex flex-col gap-3">
				{#if plan.approvers.length > 0}
					<Alert title="Then approve this computer again">
						Approve it from {listNames(plan.approvers.map((d) => d.name))}, like a new device.
					</Alert>
				{/if}
				{#if plan.waiting.length > 0}
					<Alert tone="warning" title="Devices waiting for approval are removed too">
						No approved device would be left to approve this computer, so {listNames(plan.waiting.map((d) => `“${d.name}”`))}
						{plan.waiting.length === 1 ? 'is' : 'are'} removed with it. They can ask again by signing in.
					</Alert>
				{/if}
				{#if plan.keysAtRisk}
					<Alert tone="danger" title="It’s the only device with your encryption key">
						To read your synced clips afterwards, restore this computer’s old keys from a backup in Settings → Encryption keys.
						{#if decision.matching_backup}
							cpmesh found them in {decision.matching_backup}.
						{:else if decision.backups > 0}
							cpmesh found {decision.backups === 1 ? 'a backup' : `${decision.backups} backups`} on this computer.
						{/if}
						Without one, you can start new encryption keys, but clips synced so far stay unreadable.
					</Alert>
				{/if}
			</div>
			<Button variant="danger" size="lg" class="w-full" loading={busy} onclick={() => plan && onresolve(plan.action)}>
				Replace “{plan.old.name}”
			</Button>
		{/if}
	{/if}

	{#if error}<p class="mt-3 text-xs text-danger-fg" role="alert">{error}</p>{/if}
	<button
		type="button"
		class="mt-4 text-xs text-muted hover:text-fg disabled:opacity-50"
		disabled={busy}
		onclick={oncancel}
	>
		← Cancel sign-in
	</button>
</div>
