<script lang="ts">
	import { onMount } from 'svelte';
	import { listen, type UnlistenFn } from '@tauri-apps/api/event';
	import {
		getActivity,
		getAppStateValue,
		getPendingDeviceCount,
		getRecentEntry,
		getStatusValue,
		type ActivityEvent,
	} from '#lib/store.svelte.js';
	import { connectToServer, copyEntry, disconnectFromServer, getHistory, type HistoryEntry } from '#lib/api.js';
	import { isDesktop } from '#lib/platform.js';
	import { toast } from '#lib/toast.svelte.js';
	import { contentKind, dayLabel, errorMessage, formatClock, formatSize, isMacLike, serverHost } from '#lib/ui.js';
	import Button from './ui/Button.svelte';
	import EmptyState from './ui/EmptyState.svelte';
	import Icon from './ui/Icon.svelte';
	import Kbd from './ui/Kbd.svelte';
	import Skeleton from './ui/Skeleton.svelte';
	import MeshBeam from './MeshBeam.svelte';

	/*
	 * Overview: a live status header that stays pinned, over one timeline of what
	 * moved through the mesh (clips) and what happened to it (connections, devices).
	 */

	const appState = $derived(getAppStateValue());
	const status = $derived(getStatusValue());
	const activity = $derived(getActivity());
	const recent = $derived(getRecentEntry());
	const pendingCount = $derived(getPendingDeviceCount());
	const desktop = isDesktop();

	let clips = $state<HistoryEntry[]>([]);
	let loaded = $state(false);
	let busy = $state(false);
	let copiedId = $state<string | null>(null);
	let copiedTimer: ReturnType<typeof setTimeout> | undefined;

	const meshState = $derived(
		appState === 'connected' ? 'connected' : appState === 'connecting' ? 'connecting' : ('disconnected' as const),
	);
	const host = $derived(serverHost(status?.server_url));

	const pulse = $derived(
		recent ? { key: recent.id, direction: recent.device_name === status?.device_name ? ('out' as const) : ('in' as const) } : null,
	);

	type TimelineItem =
		| { type: 'clip'; at: number; entry: HistoryEntry }
		| { type: 'event'; at: number; event: ActivityEvent };

	const timeline = $derived.by(() => {
		const items: TimelineItem[] = [
			...clips.map((entry) => ({ type: 'clip' as const, at: new Date(entry.created_at).getTime(), entry })),
			...activity.map((event) => ({ type: 'event' as const, at: event.at, event })),
		];
		items.sort((a, b) => b.at - a.at);
		const groups: { label: string; items: TimelineItem[] }[] = [];
		for (const item of items.slice(0, 16)) {
			const label = dayLabel(item.at);
			const last = groups.at(-1);
			if (last && last.label === label) last.items.push(item);
			else groups.push({ label, items: [item] });
		}
		return groups;
	});

	async function loadClips() {
		try {
			clips = (await getHistory(0, 12)).entries;
		} catch {
			// The timeline still shows session events
		} finally {
			loaded = true;
		}
	}

	async function connect() {
		busy = true;
		try {
			await connectToServer();
		} catch (e) {
			toast.error('Could not connect', errorMessage(e));
		} finally {
			busy = false;
		}
	}

	async function disconnect() {
		busy = true;
		try {
			await disconnectFromServer();
		} catch (e) {
			toast.error('Could not disconnect', errorMessage(e));
		} finally {
			busy = false;
		}
	}

	async function copy(entry: HistoryEntry) {
		try {
			await copyEntry(entry.id);
			copiedId = entry.id;
			clearTimeout(copiedTimer);
			copiedTimer = setTimeout(() => (copiedId = null), 1600);
		} catch (e) {
			toast.error('Couldn’t copy to the clipboard', errorMessage(e));
		}
	}

	onMount(() => {
		loadClips();
		let disposed = false;
		const unlisteners: UnlistenFn[] = [];
		for (const event of ['clipboard-new', 'history-synced']) {
			listen(event, () => loadClips())
				.then((unlisten) => {
					if (disposed) unlisten();
					else unlisteners.push(unlisten);
				})
				.catch(() => {});
		}
		return () => {
			disposed = true;
			clearTimeout(copiedTimer);
			unlisteners.forEach((unlisten) => unlisten());
		};
	});

	const kindIcon = { text: 'type', image: 'image', file: 'file' } as const;

	const eventStyle: Record<ActivityEvent['kind'], { icon: string; color: string }> = {
		connected: { icon: 'wifi', color: 'text-muted' },
		disconnected: { icon: 'wifi-off', color: 'text-dim' },
		'device-online': { icon: 'monitor', color: 'text-success' },
		'device-offline': { icon: 'monitor', color: 'text-dim' },
		'sync-error': { icon: 'alert-circle', color: 'text-danger' },
	};

	const headline = $derived(
		meshState === 'connected' ? 'Syncing live' : meshState === 'connecting' ? 'Connecting…' : 'Sync is paused',
	);
	const subline = $derived(
		meshState === 'connected'
			? 'What you copy here reaches your other devices within a second.'
			: meshState === 'connecting'
				? `Reaching ${host || 'your relay'}…`
				: 'This device is offline. Clips won’t sync until you connect.',
	);
</script>

<div
	class="sticky top-0 z-10 -mx-8 -mt-7 [@media(max-height:620px)]:static {pendingCount > 0 ? '[@media(max-height:700px)]:static' : ''} border-b border-border bg-bg/90 px-8 pt-7 pb-5 backdrop-blur-md max-sm:-mx-4 max-sm:px-4">
	<div class="flex items-start justify-between gap-4">
		<div class="min-w-0">
			<h1 class="flex items-center gap-2.5 text-lg font-semibold tracking-tight text-fg">
				<span
					class="status-dot {meshState === 'connected' ? 'text-accent' : meshState === 'connecting' ? 'text-warning' : 'text-border-strong'}"
					data-live={meshState !== 'disconnected'}
				></span>
				{headline}
			</h1>
			<p class="mt-0.5 text-[13px] text-muted">{subline}</p>
		</div>
		{#if meshState === 'connected'}
			<Button size="sm" icon="power" loading={busy} onclick={disconnect}>Disconnect</Button>
		{:else if meshState === 'connecting'}
			<Button size="sm" variant="ghost" loading={busy} onclick={disconnect}>Cancel</Button>
		{:else}
			<Button size="sm" variant="primary" icon="power" loading={busy} onclick={connect}>Connect</Button>
		{/if}
	</div>

	{#if pendingCount > 0}
		<a
			href="/devices"
			class="group mt-3 flex items-center gap-3 rounded-lg border border-border-strong bg-surface px-3 py-2 text-[13px] shadow-xs transition-colors hover:bg-bg-deep"
		>
			<span class="status-dot text-accent" data-live="true"></span>
			<span class="min-w-0 flex-1 truncate text-fg">
				<span class="font-medium">{pendingCount === 1 ? 'A new device wants' : `${pendingCount} new devices want`} to join your mesh.</span>
				<span class="text-muted">Compare fingerprints before you approve.</span>
			</span>
			<span class="inline-flex shrink-0 items-center gap-1 text-xs font-medium text-fg">
				Review <Icon name="arrow-right" size={12} class="transition-transform group-hover:translate-x-0.5" />
			</span>
		</a>
	{/if}

	<div class="mt-5">
		<MeshBeam
			state={meshState}
			deviceName={status?.device_name ?? ''}
			serverHost={host}
			onlineCount={status?.online_count ?? 0}
			deviceCount={status?.device_count ?? 0}
			{pulse}
		/>
	</div>
</div>

<section class="mt-7" aria-labelledby="activity-heading">
	<div class="mb-3 flex items-baseline justify-between">
		<h2 id="activity-heading" class="text-[13px] font-semibold text-fg">Activity</h2>
		<a href="/history" class="inline-flex items-center gap-1 text-xs font-medium text-muted hover:text-fg">
			All history <Icon name="arrow-right" size={12} />
		</a>
	</div>

	{#if !loaded}
		<div class="space-y-4 pl-9" aria-busy="true" aria-label="Loading activity">
			{#each [0, 1, 2] as i (i)}
				<div class="space-y-2">
					<Skeleton class="h-3.5 w-3/5" />
					<Skeleton class="h-3 w-2/5" />
				</div>
			{/each}
		</div>
	{:else if timeline.length === 0}
		<div class="rounded-xl border border-dashed border-border-strong">
			<EmptyState
				icon="arrow-down-up"
				title="Nothing has moved through your mesh yet"
				description="Copy something on this device or another one you’ve approved. It shows up here, and you can copy it back with one click."
			/>
		</div>
	{:else}
		{#each timeline as group (group.label)}
			<h3 class="mt-5 mb-1 pl-9 text-[11px] font-medium tracking-wide text-dim uppercase first:mt-0">{group.label}</h3>
			<ol class="relative">
				<!-- The rail joining the timeline's markers -->
				<span class="absolute top-3 bottom-3 left-[13px] w-px bg-border" aria-hidden="true"></span>
				{#each group.items as item (item.type === 'clip' ? `c-${item.entry.id}` : `e-${item.event.id}`)}
					{#if item.type === 'clip'}
						{@const entry = item.entry}
						{@const kind = contentKind(entry.content_type)}
						{@const copied = copiedId === entry.id}
						<li class="group relative">
							<button
								type="button"
								class="flex w-full items-start gap-3 rounded-lg py-2 pr-2 text-left transition-colors hover:bg-surface-2 focus-visible:bg-surface-2"
								onclick={() => copy(entry)}
								aria-label="Copy {kind} from {entry.device_name}: {entry.preview}"
							>
								<span
									class="relative z-[1] mt-0.5 flex h-[27px] w-[27px] shrink-0 items-center justify-center rounded-md border border-border bg-surface text-muted"
								>
									<Icon name={kindIcon[kind]} size={13} />
								</span>
								<span class="min-w-0 flex-1">
									<span
										class="line-clamp-2 text-[13px] leading-snug break-words whitespace-pre-wrap text-fg {kind === 'text' ? '' : 'font-medium'}"
										>{entry.preview || 'Empty clip'}</span
									>
									<span class="mt-0.5 block text-xs text-dim">
										{entry.device_name === status?.device_name ? 'Copied here' : `From ${entry.device_name}`} · {formatClock(
											entry.created_at,
										)}{entry.size > 0 ? ` · ${formatSize(entry.size)}` : ''}
									</span>
								</span>
								<span
									class="mt-0.5 flex shrink-0 items-center gap-1 rounded-md px-2 py-1 text-xs font-medium transition-opacity
										{copied ? 'text-success-fg opacity-100' : 'text-muted opacity-0 group-hover:opacity-100 group-focus-within:opacity-100'}"
									aria-hidden="true"
								>
									<Icon name={copied ? 'check' : 'copy'} size={13} />
									{copied ? 'Copied' : 'Copy'}
								</span>
							</button>
						</li>
					{:else}
						{@const style = eventStyle[item.event.kind]}
						<li class="relative flex items-center gap-3 py-1.5">
							<span class="relative z-[1] flex h-[27px] w-[27px] shrink-0 items-center justify-center bg-bg {style.color}">
								<Icon name={style.icon} size={13} />
							</span>
							<span class="min-w-0 flex-1 truncate text-xs text-muted" title={item.event.label}>{item.event.label}</span>
							<span class="shrink-0 pr-2 text-xs text-dim tabular-nums">{formatClock(item.event.at)}</span>
						</li>
					{/if}
				{/each}
			</ol>
		{/each}
	{/if}
</section>

{#if desktop}
	<p class="mt-10 flex flex-wrap items-center gap-x-1.5 gap-y-1 border-t border-border pt-4 text-xs text-muted">
		Closing this window keeps cpmesh syncing from the {isMacLike() ? 'menu bar' : 'system tray'}. Bring it back from anywhere with
		<Kbd keys={['mod', 'shift', 'Space']} />
	</p>
{/if}
