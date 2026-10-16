<script lang="ts">
	import { onMount } from 'svelte';
	import { listen, type UnlistenFn } from '@tauri-apps/api/event';
	import { getHistory, searchHistory, copyEntry, deleteEntry, clearHistory, syncHistory, type HistoryEntry } from '#lib/api.js';
	import { getAppStateValue, getStatusValue } from '#lib/store.svelte.js';
	import { confirmAction } from '#lib/confirm.svelte.js';
	import { toast } from '#lib/toast.svelte.js';
	import { contentKind, dayLabel, errorMessage, formatClock, formatSize, hasModKey, type ContentKind } from '#lib/ui.js';
	import Alert from '#lib/components/ui/Alert.svelte';
	import Button from '#lib/components/ui/Button.svelte';
	import EmptyState from '#lib/components/ui/EmptyState.svelte';
	import Field from '#lib/components/ui/Field.svelte';
	import Icon from '#lib/components/ui/Icon.svelte';
	import Kbd from '#lib/components/ui/Kbd.svelte';
	import PageHeader from '#lib/components/ui/PageHeader.svelte';
	import Segmented from '#lib/components/ui/Segmented.svelte';
	import Skeleton from '#lib/components/ui/Skeleton.svelte';

	let entries = $state<HistoryEntry[]>([]);
	let hasMore = $state(false);
	let page = $state(0);
	let query = $state('');
	let loading = $state(true);
	let loadingMore = $state(false);
	let error = $state('');
	let searchTimeout: ReturnType<typeof setTimeout>;
	let syncing = $state(false);
	let copiedId = $state<string | null>(null);
	let copiedTimer: ReturnType<typeof setTimeout> | undefined;
	let deletingId = $state<string | null>(null);
	let clearing = $state(false);
	let filter = $state<'all' | ContentKind>('all');
	let searchInput = $state<HTMLInputElement | null>(null);

	const appState = $derived(getAppStateValue());
	const status = $derived(getStatusValue());
	const searching = $derived(query.trim().length > 0);

	const visible = $derived(filter === 'all' ? entries : entries.filter((e) => contentKind(e.content_type) === filter));

	const groups = $derived.by(() => {
		const out: { label: string; items: HistoryEntry[] }[] = [];
		for (const entry of visible) {
			const label = dayLabel(entry.created_at);
			const last = out.at(-1);
			if (last && last.label === label) last.items.push(entry);
			else out.push({ label, items: [entry] });
		}
		return out;
	});

	async function loadHistory() {
		if (page === 0) loading = true;
		else loadingMore = true;
		error = '';
		try {
			const result = await getHistory(page);
			entries = page === 0 ? result.entries : [...entries, ...result.entries];
			hasMore = result.has_more;
		} catch (e) {
			error = `Couldn’t load your history. ${errorMessage(e)}`;
		} finally {
			loading = false;
			loadingMore = false;
		}
	}

	async function doSearch() {
		if (!searching) {
			page = 0;
			await loadHistory();
			return;
		}
		loading = true;
		error = '';
		try {
			entries = await searchHistory(query);
			hasMore = false;
		} catch (e) {
			error = `Search failed. ${errorMessage(e)}`;
		} finally {
			loading = false;
		}
	}

	function onSearchInput() {
		clearTimeout(searchTimeout);
		searchTimeout = setTimeout(doSearch, 250);
	}

	function clearSearch() {
		query = '';
		clearTimeout(searchTimeout);
		doSearch();
		searchInput?.focus();
	}

	async function handleCopy(entry: HistoryEntry) {
		try {
			await copyEntry(entry.id);
			copiedId = entry.id;
			clearTimeout(copiedTimer);
			copiedTimer = setTimeout(() => (copiedId = null), 1600);
		} catch (e) {
			toast.error('Couldn’t copy to the clipboard', errorMessage(e));
		}
	}

	async function handleDelete(entry: HistoryEntry) {
		if (deletingId) return;
		deletingId = entry.id;
		try {
			await deleteEntry(entry.id);
			entries = entries.filter((e) => e.id !== entry.id);
		} catch (e) {
			toast.error('Couldn’t delete the clip', errorMessage(e));
		} finally {
			deletingId = null;
		}
	}

	async function handleClear() {
		const confirmed = await confirmAction({
			title: 'Clear clipboard history?',
			description: 'Every clip in this history is deleted. This can’t be undone.',
			confirmLabel: 'Clear history',
			tone: 'danger',
		});
		if (!confirmed) return;
		clearing = true;
		try {
			await clearHistory();
			entries = [];
			hasMore = false;
			toast.success('History cleared');
		} catch (e) {
			toast.error('Couldn’t clear history', errorMessage(e));
		} finally {
			clearing = false;
		}
	}

	function loadMore() {
		page++;
		loadHistory();
	}

	async function handleSync() {
		syncing = true;
		try {
			const count = await syncHistory();
			toast.success(count === 0 ? 'Already up to date' : `Synced ${count} ${count === 1 ? 'clip' : 'clips'} from your server`);
			page = 0;
			if (searching) await doSearch();
			else await loadHistory();
		} catch (e) {
			toast.error('Sync failed', errorMessage(e));
		} finally {
			syncing = false;
		}
	}

	// ⌘/Ctrl+F or "/" jumps to search; Escape clears it
	function onKeydown(event: KeyboardEvent) {
		const target = event.target as HTMLElement | null;
		const typing = target?.closest('input, textarea, select, [contenteditable="true"]');
		if ((hasModKey(event) && event.key.toLowerCase() === 'f') || (event.key === '/' && !typing)) {
			event.preventDefault();
			searchInput?.focus();
			searchInput?.select();
		} else if (event.key === 'Escape' && target === searchInput && query) {
			event.preventDefault();
			clearSearch();
		}
	}

	onMount(() => {
		loadHistory();
		let disposed = false;
		const unlisteners: UnlistenFn[] = [];
		for (const event of ['clipboard-new', 'history-synced']) {
			listen(event, () => {
				page = 0;
				if (searching) doSearch();
				else loadHistory();
			})
				.then((unlisten) => {
					if (disposed) unlisten();
					else unlisteners.push(unlisten);
				})
				.catch((cause) => {
					error = `Live updates are unavailable: ${errorMessage(cause)}`;
				});
		}
		return () => {
			disposed = true;
			clearTimeout(searchTimeout);
			clearTimeout(copiedTimer);
			unlisteners.forEach((unlisten) => unlisten());
		};
	});

	const kindIcon = { text: 'type', image: 'image', file: 'file' } as const;
</script>

<svelte:window onkeydown={onKeydown} />

<svelte:head>
	<title>History · cpmesh</title>
</svelte:head>

<PageHeader title="History" description="Everything copied across your devices. Click a clip to copy it again.">
	{#snippet actions()}
		{#if appState === 'connected'}
			<Button size="sm" icon="refresh" loading={syncing} onclick={handleSync}>{syncing ? 'Syncing…' : 'Sync from server'}</Button>
		{/if}
		{#if entries.length > 0 && !searching}
			<Button size="sm" variant="ghost" icon="trash" loading={clearing} onclick={handleClear}>Clear all</Button>
		{/if}
	{/snippet}
</PageHeader>

<div class="sticky top-0 z-10 -mx-2 mb-2 flex flex-wrap items-center gap-3 bg-bg/90 px-2 py-2 backdrop-blur-md">
	<Field
		class="min-w-[220px] flex-1"
		type="search"
		icon="search"
		placeholder="Search clips"
		aria-label="Search clipboard history"
		autocomplete="off"
		spellcheck={false}
		bind:value={query}
		bind:input={searchInput}
		oninput={onSearchInput}
	>
		{#snippet trailing()}
			{#if query}
				<button
					type="button"
					class="flex h-6 w-6 items-center justify-center rounded text-dim hover:bg-surface-2 hover:text-fg"
					aria-label="Clear search"
					onclick={clearSearch}
				>
					<Icon name="x" size={13} />
				</button>
			{:else}
				<Kbd keys={['mod', 'F']} class="pointer-events-none" />
			{/if}
		{/snippet}
	</Field>
	<Segmented
		label="Clip type"
		bind:value={filter}
		options={[
			{ value: 'all', label: 'All' },
			{ value: 'text', label: 'Text' },
			{ value: 'image', label: 'Images' },
			{ value: 'file', label: 'Files' },
		]}
	/>
</div>

{#if error}
	<Alert tone="danger" class="mb-4" ondismiss={() => (error = '')}>{error}</Alert>
{/if}

{#if loading}
	<div class="divide-y divide-border rounded-xl border border-border" aria-busy="true" aria-label="Loading history">
		{#each [0, 1, 2, 3, 4] as i (i)}
			<div class="flex items-start gap-3 px-4 py-3.5">
				<Skeleton class="h-8 w-8 rounded-md" />
				<div class="flex-1 space-y-2 pt-0.5">
					<Skeleton class="h-3.5 {i % 2 ? 'w-2/3' : 'w-4/5'}" />
					<Skeleton class="h-3 w-1/3" />
				</div>
			</div>
		{/each}
	</div>
{:else if visible.length === 0}
	<div class="rounded-xl border border-dashed border-border-strong">
		{#if searching}
			<EmptyState icon="search" title="No clips match “{query.trim()}”" description="Search looks through text, file names and device names.">
				<Button size="sm" onclick={clearSearch}>Clear search</Button>
			</EmptyState>
		{:else if filter !== 'all' && entries.length > 0}
			<EmptyState
				icon={kindIcon[filter]}
				title="No {filter === 'image' ? 'images' : filter === 'file' ? 'files' : 'text clips'} loaded"
				description={hasMore ? 'Older clips may match — load more or show everything.' : undefined}
			>
				<Button size="sm" onclick={() => (filter = 'all')}>Show all clips</Button>
			</EmptyState>
		{:else}
			<EmptyState
				icon="clipboard"
				title="Your history is empty"
				description="Copy text, an image or a file on any approved device and it appears here, ready to copy again."
			>
				{#if appState === 'connected'}
					<Button size="sm" icon="refresh" loading={syncing} onclick={handleSync}>Sync from server</Button>
				{/if}
			</EmptyState>
		{/if}
	</div>
{:else}
	{#each groups as group (group.label)}
		<h2 class="mt-5 mb-2 px-1 text-[11px] font-medium tracking-wide text-dim uppercase first:mt-2">{group.label}</h2>
		<ul class="divide-y divide-border overflow-hidden rounded-xl border border-border bg-surface">
			{#each group.items as entry (entry.id)}
				{@const kind = contentKind(entry.content_type)}
				{@const copied = copiedId === entry.id}
				<li class="group relative flex items-start transition-colors hover:bg-bg-deep">
					<button
						type="button"
						class="flex min-w-0 flex-1 items-start gap-3 px-4 py-3 text-left outline-none focus-visible:bg-bg-deep focus-visible:shadow-[inset_2px_0_0_var(--color-ink)]"
						onclick={() => handleCopy(entry)}
						aria-label="Copy {kind} from {entry.device_name}: {entry.preview}"
					>
						<span class="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border bg-bg-deep text-muted">
							<Icon name={kindIcon[kind]} size={14} />
						</span>
						<span class="min-w-0 flex-1">
							<span
								class="line-clamp-3 text-[13px] leading-snug break-words whitespace-pre-wrap text-fg {kind === 'text' ? '' : 'font-medium'}"
								>{entry.preview || 'Empty clip'}</span
							>
							<span class="mt-1 flex items-center gap-1.5 text-xs text-dim">
								<span class="truncate">{entry.device_name === status?.device_name ? 'This device' : entry.device_name}</span>
								<span aria-hidden="true">·</span>
								<span class="shrink-0 tabular-nums">{formatClock(entry.created_at)}</span>
								{#if entry.size > 0}
									<span aria-hidden="true">·</span>
									<span class="shrink-0 tabular-nums">{formatSize(entry.size)}</span>
								{/if}
							</span>
						</span>
					</button>
					<div class="flex shrink-0 items-center gap-0.5 py-2.5 pr-3">
						<span
							class="flex items-center gap-1 px-1.5 text-xs font-medium transition-opacity {copied
								? 'text-success-fg opacity-100'
								: 'pointer-events-none text-muted opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 pointer-coarse:hidden'}"
							aria-live="polite"
						>
							<Icon name={copied ? 'check' : 'copy'} size={13} />
							{copied ? 'Copied' : 'Copy'}
						</span>
						<button
							type="button"
							class="flex h-7 w-7 items-center justify-center rounded-md text-dim opacity-0 transition-[opacity,color,background-color] group-hover:opacity-100 group-focus-within:opacity-100 hover:bg-danger-soft hover:text-danger focus-visible:opacity-100 disabled:opacity-40 pointer-coarse:opacity-100"
							aria-label="Delete clip"
							title="Delete"
							disabled={deletingId === entry.id}
							onclick={() => handleDelete(entry)}
						>
							<Icon
								name={deletingId === entry.id ? 'loader' : 'trash'}
								size={14}
								class={deletingId === entry.id ? 'animate-[spin_0.8s_linear_infinite]' : ''}
							/>
						</button>
					</div>
				</li>
			{/each}
		</ul>
	{/each}

	{#if hasMore}
		<div class="mt-4 flex justify-center">
			<Button size="sm" loading={loadingMore} onclick={loadMore}>Load older clips</Button>
		</div>
	{/if}
{/if}
