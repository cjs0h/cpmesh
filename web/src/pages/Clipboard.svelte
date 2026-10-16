<script lang="ts">
  import { onMount } from 'svelte';
  import { clipboardState, fetchClipboard, loadNextPage, loadPrevPage, deleteEntry, clearAll } from '../lib/stores/clipboard.svelte';
  import { connectionState } from '../lib/stores/connection.svelte';
  import { toast } from '../lib/stores/toast.svelte';
  import { createClock } from '../lib/clock.svelte';
  import { absoluteTime, contentTypeMeta, formatBytes, relativeTime, truncateMiddle } from '../lib/format';
  import Icon from '../components/Icon.svelte';
  import Badge from '../components/ui/Badge.svelte';
  import Button from '../components/ui/Button.svelte';
  import Card from '../components/ui/Card.svelte';
  import ConfirmAction from '../components/ui/ConfirmAction.svelte';
  import EmptyState from '../components/ui/EmptyState.svelte';
  import IconTile from '../components/ui/IconTile.svelte';
  import Skeleton from '../components/ui/Skeleton.svelte';
  import CopyButton from '../components/ui/CopyButton.svelte';
  import Alert from '../components/ui/Alert.svelte';

  const clock = createClock();
  let filter = $state<string>('all');
  let query = $state('');

  onMount(() => {
    fetchClipboard(true);
  });

  const types = $derived.by(() => {
    const counts = new Map<string, number>();
    for (const e of clipboardState.entries) {
      const key = contentTypeMeta(e.content_type).label;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  });

  const visible = $derived(
    clipboardState.entries.filter((e) => {
      if (filter !== 'all' && contentTypeMeta(e.content_type).label !== filter) return false;
      if (query.trim()) {
        const q = query.trim().toLowerCase();
        return (e.device_name || '').toLowerCase().includes(q) || e.content_type.toLowerCase().includes(q) || e.id.toLowerCase().includes(q);
      }
      return true;
    })
  );

  const page = $derived(Math.floor(clipboardState.offset / 20) + 1);
  const totalBytes = $derived(clipboardState.entries.reduce((sum, e) => sum + e.encrypted_size, 0));

  async function handleDelete(id: string) {
    try {
      await deleteEntry(id);
      toast.success('Entry deleted');
    } catch (err: any) {
      toast.error('Could not delete entry', err.message);
    }
  }

  async function handleClearAll() {
    try {
      await clearAll();
      toast.success('Clipboard history cleared');
    } catch (err: any) {
      toast.error('Could not clear history', err.message);
    }
  }
</script>

<!-- Toolbar -->
{#if clipboardState.error}<Alert tone="danger">{clipboardState.error} The last loaded page is unchanged.</Alert>{/if}
<div class="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
  <div class="flex flex-wrap items-center gap-2">
    <button
      type="button"
      class="h-8 rounded-md border px-3 text-[13px] font-medium transition-colors duration-150 {filter === 'all' ? 'border-ink bg-ink text-white' : 'border-border bg-surface text-muted hover:border-border-strong hover:text-fg'}"
      onclick={() => (filter = 'all')}
    >
      All <span class="ml-1 opacity-60">{clipboardState.entries.length}</span>
    </button>
    {#each types as [label, count] (label)}
      <button
        type="button"
        class="h-8 rounded-md border px-3 text-[13px] font-medium transition-colors duration-150 {filter === label ? 'border-ink bg-ink text-white' : 'border-border bg-surface text-muted hover:border-border-strong hover:text-fg'}"
        onclick={() => (filter = filter === label ? 'all' : label)}
      >
        {label} <span class="ml-1 opacity-60">{count}</span>
      </button>
    {/each}
  </div>

  <div class="flex items-center gap-2">
    <div class="relative">
      <span class="pointer-events-none absolute inset-y-0 left-3 flex items-center text-dim"><Icon name="search" size={14} /></span>
      <input
        type="search"
        bind:value={query}
        placeholder="Filter by device…"
        class="h-9 w-full rounded-md border border-border bg-surface pl-9 pr-3 text-[13px] text-fg shadow-xs outline-none transition-[border-color,box-shadow] duration-150 placeholder:text-dim hover:border-border-strong focus:border-ink focus:shadow-[0_0_0_3px_rgba(10,10,10,0.08)] sm:w-56"
      />
    </div>
    {#if clipboardState.entries.length > 0}
      <ConfirmAction label="Clear all" confirmLabel="Yes, clear everything" prompt="Delete all entries?" variant="danger-soft" onconfirm={handleClearAll} />
    {/if}
  </div>
</div>

<Card padded={false}>
  {#if clipboardState.loading && clipboardState.entries.length === 0}
    <div class="flex flex-col gap-3 p-5">
      {#each Array(6) as _, i (i)}
        <div class="flex items-center gap-3">
          <Skeleton class="h-9 w-9" rounded="rounded-lg" />
          <div class="flex-1"><Skeleton class="mb-2 h-3 w-1/4" /><Skeleton class="h-3 w-1/6" /></div>
          <Skeleton class="h-3 w-16" />
          <Skeleton class="h-3 w-12" />
        </div>
      {/each}
    </div>
  {:else if clipboardState.entries.length === 0}
    <div class="p-5">
      <EmptyState icon="clipboard" title="Your history is empty" description="Copy text, an image or a file on any paired device. It is encrypted on-device and appears here within a second.">
        <Button variant="outline" size="sm" icon="monitor" href="#/devices">Pair a device</Button>
      </EmptyState>
    </div>
  {:else if visible.length === 0}
    <div class="p-5">
      <EmptyState icon="filter" title="No matching entries" description="Try a different type filter or clear the device search." compact>
        <Button variant="ghost" size="sm" onclick={() => { filter = 'all'; query = ''; }}>Reset filters</Button>
      </EmptyState>
    </div>
  {:else}
    <div class="overflow-x-auto">
      <table class="tbl min-w-[720px]">
        <thead>
          <tr>
            <th>Type</th>
            <th>Device</th>
            <th>Size</th>
            <th>Entry ID</th>
            <th>When</th>
            <th class="text-right"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each visible as entry (entry.id)}
            {@const meta = contentTypeMeta(entry.content_type)}
            <tr>
              <td>
                <div class="flex items-center gap-3">
                  <IconTile icon={meta.icon} tone={meta.tone} size={32} />
                  <span class="font-medium text-fg">{meta.label}</span>
                </div>
              </td>
              <td class="text-muted">{entry.device_name || 'Unknown device'}</td>
              <td class="font-mono text-[12.5px] text-muted">{formatBytes(entry.encrypted_size)}</td>
              <td>
                <span class="inline-flex items-center gap-1">
                  <span class="mono-chip">{truncateMiddle(entry.id, 5)}</span>
                  <CopyButton text={entry.id} label="Copy entry ID" size={12} />
                </span>
              </td>
              <td class="text-muted">
                <time datetime={entry.created_at} title={absoluteTime(entry.created_at)}>{relativeTime(entry.created_at, clock.now)}</time>
              </td>
              <td class="text-right">
                <ConfirmAction size="icon-sm" variant="ghost" label="Delete entry" confirmLabel="Delete" prompt="Delete?" onconfirm={() => handleDelete(entry.id)} />
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    <!-- Footer -->
    <div class="flex flex-col gap-3 border-t border-border bg-bg-deep px-5 py-3 sm:flex-row sm:items-center sm:justify-between">
      <div class="flex items-center gap-3 text-[12.5px] text-dim">
        <span>{visible.length} of {clipboardState.entries.length} on this page</span>
        <span aria-hidden="true">·</span>
        <span class="font-mono">{formatBytes(totalBytes)} ciphertext</span>
        {#if connectionState.status === 'online' && clipboardState.offset === 0}
          <Badge tone="mint" dot live>Live</Badge>
        {/if}
      </div>
      <div class="flex items-center gap-2">
        <Button variant="outline" size="sm" icon="chevron-left" disabled={clipboardState.offset === 0 || clipboardState.loading} onclick={loadPrevPage}>Newer</Button>
        <span class="px-1 font-mono text-[12px] text-muted">Page {page}</span>
        <Button variant="outline" size="sm" iconRight="chevron-right" disabled={!clipboardState.hasMore || clipboardState.loading} onclick={loadNextPage}>Older</Button>
      </div>
    </div>
  {/if}
</Card>
