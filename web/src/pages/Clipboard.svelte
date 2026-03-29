<script lang="ts">
  import {
    clipboardState,
    fetchClipboard,
    loadNextPage,
    loadPrevPage,
    deleteEntry,
    clearAll,
  } from '../lib/stores/clipboard.svelte';
  import Icon from '../components/Icon.svelte';

  let showClearConfirm = $state(false);

  $effect(() => {
    fetchClipboard(true);
  });

  async function handleDelete(id: string) {
    await deleteEntry(id);
  }

  async function handleClearAll() {
    await clearAll();
    showClearConfirm = false;
  }
</script>

<div>
  <div class="flex items-center justify-between mb-5 flex-wrap gap-3">
    <h2 class="text-xl font-semibold">Clipboard History</h2>
    {#if clipboardState.entries.length > 0}
      {#if showClearConfirm}
        <div class="flex items-center gap-2">
          <span class="text-[13px] text-warning font-medium">Clear all entries?</span>
          <button class="inline-flex items-center gap-1.5 px-4 py-2 border border-danger rounded bg-danger text-white text-[13px] font-medium transition-all duration-150 hover:bg-danger-hover" onclick={handleClearAll}>Yes, clear</button>
          <button class="inline-flex items-center gap-1.5 px-4 py-2 border border-border rounded bg-transparent text-muted text-[13px] font-medium transition-all duration-150 hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => (showClearConfirm = false)}>Cancel</button>
        </div>
      {:else}
        <button class="inline-flex items-center gap-1.5 px-4 py-2 bg-transparent text-danger border border-danger/30 rounded text-[13px] font-medium transition-all duration-150 hover:bg-danger-glow hover:border-danger" onclick={() => (showClearConfirm = true)}>
          <Icon name="trash" size={14} /> Clear All
        </button>
      {/if}
    {/if}
  </div>

  {#if clipboardState.loading}
    <div class="flex items-center gap-2.5 p-6 text-muted text-sm">
      <span class="inline-block w-4 h-4 border-2 border-border border-t-primary rounded-full animate-[spin_0.6s_linear_infinite]"></span>
      <span>Loading...</span>
    </div>
  {:else if clipboardState.entries.length === 0}
    <div class="text-center py-15 px-4 bg-bg-card border border-border rounded-xl">
      <div class="text-dim mb-4"><Icon name="clipboard" size={32} /></div>
      <p class="mb-1 font-medium">No clipboard entries yet.</p>
      <p class="text-muted text-[13px]">Entries will appear here when you copy content on a connected device.</p>
    </div>
  {:else}
    <div class="bg-bg-card border border-border rounded-xl overflow-hidden">
      <table class="w-full border-collapse">
        <thead>
          <tr>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Type</th>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Device</th>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Size</th>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Time</th>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold"></th>
          </tr>
        </thead>
        <tbody>
          {#each clipboardState.entries as entry}
            <tr class="transition-colors duration-150 hover:bg-bg-hover">
              <td class="px-[18px] py-[13px] text-sm border-b border-border last:border-b-0">
                <span class="inline-block px-2.5 py-[3px] rounded-full bg-primary-glow text-[11px] font-semibold uppercase tracking-[0.04em] text-primary border border-primary/15">{entry.content_type}</span>
              </td>
              <td class="px-[18px] py-[13px] text-sm border-b border-border font-medium">{entry.device_name || 'Unknown'}</td>
              <td class="px-[18px] py-[13px] text-[13px] border-b border-border text-muted">{entry.encrypted_data ? Math.ceil(entry.encrypted_data.length * 0.75) + ' B' : '-'}</td>
              <td class="px-[18px] py-[13px] text-[13px] border-b border-border text-muted">{new Date(entry.created_at).toLocaleString()}</td>
              <td class="px-[18px] py-[13px] text-sm border-b border-border">
                <button class="bg-transparent border-none text-dim p-1.5 rounded transition-all duration-150 flex items-center hover:text-danger hover:bg-danger-glow" title="Delete" onclick={() => handleDelete(entry.id)}>
                  <Icon name="trash" size={14} />
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    <div class="flex items-center justify-center gap-4 mt-4">
      <button class="inline-flex items-center gap-1.5 px-4 py-2 border border-border rounded bg-transparent text-muted text-[13px] font-medium transition-all duration-150 hover:not-disabled:bg-bg-hover hover:not-disabled:text-text hover:not-disabled:border-border-hover disabled:opacity-35 disabled:cursor-default" disabled={clipboardState.offset === 0} onclick={loadPrevPage}>
        <Icon name="arrow-left" size={14} /> Previous
      </button>
      <span class="text-[13px] text-muted font-medium">Page {Math.floor(clipboardState.offset / 20) + 1}</span>
      <button class="inline-flex items-center gap-1.5 px-4 py-2 border border-border rounded bg-transparent text-muted text-[13px] font-medium transition-all duration-150 hover:not-disabled:bg-bg-hover hover:not-disabled:text-text hover:not-disabled:border-border-hover disabled:opacity-35 disabled:cursor-default" disabled={!clipboardState.hasMore} onclick={loadNextPage}>
        Next <Icon name="chevron-right" size={14} />
      </button>
    </div>
  {/if}
</div>
