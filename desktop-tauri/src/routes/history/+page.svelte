<script lang="ts">
	import { onMount } from 'svelte';
	import { getHistory, searchHistory, copyEntry, deleteEntry, clearHistory, syncHistory, type HistoryEntry, type HistoryPage } from '#lib/api.js';
	import { listen, type UnlistenFn } from '@tauri-apps/api/event';
	import { getAppStateValue } from '#lib/store.svelte.js';

	let entries = $state<HistoryEntry[]>([]);
	let hasMore = $state(false);
	let page = $state(0);
	let query = $state('');
	let loading = $state(false);
	let error = $state('');
	let searchTimeout: ReturnType<typeof setTimeout>;
	let syncing = $state(false);
	let syncMsg = $state('');
	let copyingId = $state<string | null>(null);
	let deletingId = $state<string | null>(null);
	let clearing = $state(false);

	const appState = $derived(getAppStateValue());

	async function loadHistory() {
		loading = true;
		error = '';
		try {
			const result = await getHistory(page);
			if (page === 0) {
				entries = result.entries;
			} else {
				entries = [...entries, ...result.entries];
			}
			hasMore = result.has_more;
		} catch (e) {
			error = 'Failed to load history.';
			console.error('loadHistory:', e);
		} finally {
			loading = false;
		}
	}

	async function doSearch() {
		if (!query.trim()) {
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
			error = 'Search failed.';
			console.error('doSearch:', e);
		} finally {
			loading = false;
		}
	}

	function onSearchInput() {
		clearTimeout(searchTimeout);
		searchTimeout = setTimeout(doSearch, 300);
	}

	async function handleCopy(id: string) {
		if (copyingId) return;
		copyingId = id;
		try {
			await copyEntry(id);
		} catch (e) {
			error = 'Failed to copy to clipboard.';
			console.error('handleCopy:', e);
		} finally {
			copyingId = null;
		}
	}

	async function handleDelete(id: string) {
		if (deletingId) return;
		deletingId = id;
		try {
			await deleteEntry(id);
			entries = entries.filter((e) => e.id !== id);
		} catch (e) {
			error = 'Failed to delete entry.';
			console.error('handleDelete:', e);
		} finally {
			deletingId = null;
		}
	}

	async function handleClear() {
		if (!confirm('Clear all clipboard history? This cannot be undone.')) return;
		clearing = true;
		try {
			await clearHistory();
			entries = [];
		} catch (e) {
			error = 'Failed to clear history.';
			console.error('handleClear:', e);
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
		syncMsg = '';
		try {
			const count = await syncHistory();
			syncMsg = `Synced ${count} entries from server`;
			page = 0;
			await loadHistory();
			setTimeout(() => { syncMsg = ''; }, 3000);
		} catch (e) {
			syncMsg = `Sync failed: ${e}`;
			setTimeout(() => { syncMsg = ''; }, 5000);
		} finally {
			syncing = false;
		}
	}

	function formatTime(iso: string): string {
		const d = new Date(iso);
		const now = new Date();
		const diff = now.getTime() - d.getTime();
		if (diff < 60000) return 'Just now';
		if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
		if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
		return d.toLocaleDateString();
	}

	function formatSize(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / 1048576).toFixed(1)} MB`;
	}

	function iconForType(type: string): string {
		switch (type) {
			case 'image': return '🖼';
			case 'file': return '📄';
			default: return '📋';
		}
	}

	onMount(() => {
		loadHistory();
		let disposed = false;
		const unlisteners: UnlistenFn[] = [];
		for (const event of ['clipboard-new', 'history-synced']) {
			listen(event, () => {
				page = 0;
				if (query.trim()) doSearch(); else loadHistory();
			}).then((unlisten) => {
				if (disposed) unlisten(); else unlisteners.push(unlisten);
			}).catch((cause) => { error = `History notifications unavailable: ${cause}`; });
		}
		return () => {
			disposed = true;
			clearTimeout(searchTimeout);
			unlisteners.forEach((unlisten) => unlisten());
		};
	});
</script>

<div class="history-page">
	<div class="header">
		<h1>Clipboard History</h1>
		<div class="header-actions">
			{#if appState === 'connected'}
				<button onclick={handleSync} disabled={syncing}>
					{syncing ? 'Syncing...' : 'Sync from Server'}
				</button>
			{/if}
			{#if entries.length > 0}
				<button class="danger" onclick={handleClear} disabled={clearing}>
					{clearing ? 'Clearing...' : 'Clear All'}
				</button>
			{/if}
		</div>
	</div>

	{#if syncMsg}
		<p class="sync-msg">{syncMsg}</p>
	{/if}

	{#if error}
		<p class="error-msg">{error}</p>
	{/if}

	<div class="search">
		<input type="text" placeholder="Search clipboard history..." bind:value={query} oninput={onSearchInput} />
	</div>

	<div class="entries">
		{#each entries as entry (entry.id)}
			<div class="entry card">
				<div class="entry-icon">{iconForType(entry.content_type)}</div>
				<div class="entry-content">
					<div class="entry-preview">{entry.preview}</div>
					<div class="entry-meta">
						<span>{entry.device_name}</span>
						<span>·</span>
						<span>{formatTime(entry.created_at)}</span>
						{#if entry.size > 0}
							<span>·</span>
							<span>{formatSize(entry.size)}</span>
						{/if}
					</div>
				</div>
				<div class="entry-actions">
					<button
						onclick={() => handleCopy(entry.id)}
						title="Copy"
						disabled={copyingId === entry.id}
					>
						{copyingId === entry.id ? '⏳' : '📋'}
					</button>
					<button
						onclick={() => handleDelete(entry.id)}
						title="Delete"
						disabled={deletingId === entry.id}
					>
						{deletingId === entry.id ? '⏳' : '🗑'}
					</button>
				</div>
			</div>
		{/each}

		{#if entries.length === 0 && !loading}
			<p class="empty">No clipboard history yet</p>
		{/if}

		{#if loading}
			<p class="empty">Loading...</p>
		{/if}

		{#if hasMore && !loading}
			<button class="load-more" onclick={loadMore} disabled={loading}>
				Load More
			</button>
		{/if}
	</div>
</div>

<style>
	.history-page h1 {
		font-size: 1.25rem;
	}

	.header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}

	.header-actions {
		display: flex;
		gap: 0.5rem;
	}

	.sync-msg {
		font-size: 0.8125rem;
		color: var(--text-secondary);
		margin-bottom: 0.75rem;
	}

	.error-msg {
		color: var(--danger, #ef4444);
		font-size: 0.8rem;
		margin-bottom: 0.75rem;
		padding: 0.5rem;
		background: rgba(239, 68, 68, 0.1);
		border-radius: var(--radius, 0.5rem);
	}

	.search {
		margin-bottom: 1rem;
	}

	.entries {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.entry {
		display: flex;
		align-items: flex-start;
		gap: 0.75rem;
		padding: 0.75rem;
	}

	.entry-icon {
		font-size: 1.25rem;
		flex-shrink: 0;
		margin-top: 2px;
	}

	.entry-content {
		flex: 1;
		min-width: 0;
	}

	.entry-preview {
		font-size: 0.875rem;
		white-space: pre-wrap;
		word-break: break-word;
		max-height: 4.5em;
		overflow: hidden;
	}

	.entry-meta {
		display: flex;
		gap: 0.375rem;
		font-size: 0.75rem;
		color: var(--text-secondary);
		margin-top: 0.25rem;
	}

	.entry-actions {
		display: flex;
		gap: 0.25rem;
		flex-shrink: 0;
	}

	.entry-actions button {
		border: none;
		background: none;
		padding: 0.25rem;
		font-size: 0.875rem;
		opacity: 0.5;
	}

	.entry-actions button:hover:not(:disabled) {
		opacity: 1;
	}

	.entry-actions button:disabled {
		opacity: 0.3;
		cursor: not-allowed;
	}

	.empty {
		text-align: center;
		color: var(--text-secondary);
		padding: 3rem 0;
	}

	.load-more {
		width: 100%;
		margin-top: 0.5rem;
	}

	@media (max-width: 768px) {
		.header {
			flex-direction: column;
			align-items: flex-start;
			gap: 0.5rem;
		}

		.header-actions {
			width: 100%;
		}

		.header-actions button {
			flex: 1;
		}

		.entry-actions {
			opacity: 1;
		}

		.entry-actions button {
			min-width: 44px;
			min-height: 44px;
			display: flex;
			align-items: center;
			justify-content: center;
		}
	}
</style>
