<script lang="ts">
  import { devicesState, fetchDevices } from '../lib/stores/devices.svelte';
  import { clipboardState, fetchClipboard } from '../lib/stores/clipboard.svelte';
  import Icon from '../components/Icon.svelte';

  $effect(() => {
    fetchDevices();
    fetchClipboard(true);
  });

  let onlineCount = $derived(devicesState.list.filter((d) => d.online).length);
</script>

<div>
  <div class="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-4 mb-8">
    <div class="bg-bg-card border border-border rounded-xl p-[22px] flex items-center gap-4 transition-all duration-200 hover:border-border-hover hover:shadow-md" style="--accent: var(--color-primary); --accent-glow: var(--color-primary-glow);">
      <div class="w-11 h-11 rounded-lg bg-[var(--accent-glow)] border border-[color-mix(in_srgb,var(--accent)_20%,transparent)] text-[var(--accent)] flex items-center justify-center shrink-0">
        <Icon name="monitor" size={20} />
      </div>
      <div>
        <div class="text-[13px] text-muted mb-0.5 font-medium">Devices</div>
        <div class="text-[28px] font-bold tracking-[-0.02em]">{devicesState.list.length}</div>
      </div>
    </div>
    <div class="bg-bg-card border border-border rounded-xl p-[22px] flex items-center gap-4 transition-all duration-200 hover:border-border-hover hover:shadow-md" style="--accent: var(--color-success); --accent-glow: var(--color-success-glow);">
      <div class="w-11 h-11 rounded-lg bg-[var(--accent-glow)] border border-[color-mix(in_srgb,var(--accent)_20%,transparent)] text-[var(--accent)] flex items-center justify-center shrink-0">
        <Icon name="wifi" size={20} />
      </div>
      <div>
        <div class="text-[13px] text-muted mb-0.5 font-medium">Online</div>
        <div class="text-[28px] font-bold tracking-[-0.02em] text-success">{onlineCount}</div>
      </div>
    </div>
    <div class="bg-bg-card border border-border rounded-xl p-[22px] flex items-center gap-4 transition-all duration-200 hover:border-border-hover hover:shadow-md" style="--accent: var(--color-warning); --accent-glow: var(--color-warning-glow);">
      <div class="w-11 h-11 rounded-lg bg-[var(--accent-glow)] border border-[color-mix(in_srgb,var(--accent)_20%,transparent)] text-[var(--accent)] flex items-center justify-center shrink-0">
        <Icon name="clipboard" size={20} />
      </div>
      <div>
        <div class="text-[13px] text-muted mb-0.5 font-medium">Clipboard Entries</div>
        <div class="text-[28px] font-bold tracking-[-0.02em]">{clipboardState.entries.length}{clipboardState.hasMore ? '+' : ''}</div>
      </div>
    </div>
  </div>

  {#if clipboardState.entries.length > 0}
    <h3 class="text-[15px] mb-3 text-muted font-semibold">Recent Entries</h3>
    <div class="bg-bg-card border border-border rounded-xl overflow-hidden">
      {#each clipboardState.entries.slice(0, 5) as entry, i}
        <div class="flex items-center gap-4 px-[18px] py-[13px] border-b border-border text-sm transition-colors duration-150 hover:bg-bg-hover last:border-b-0">
          <span class="inline-block px-2.5 py-[3px] rounded-full bg-primary-glow text-[11px] font-semibold uppercase tracking-[0.04em] text-primary border border-primary/15">{entry.content_type}</span>
          <span class="flex-1 text-text font-medium">{entry.device_name || 'Unknown'}</span>
          <span class="flex items-center gap-[5px] text-muted text-[13px]">
            <Icon name="clock" size={13} />
            {new Date(entry.created_at).toLocaleString()}
          </span>
        </div>
      {/each}
    </div>
  {:else}
    <div class="text-center py-15 px-6 bg-bg-card border border-border rounded-xl">
      <div class="text-dim mb-4">
        <Icon name="clipboard" size={32} />
      </div>
      <p class="mb-1 font-medium">No clipboard entries yet</p>
      <p class="text-muted text-[13px]">Entries will appear here when you copy content on a connected device.</p>
    </div>
  {/if}
</div>
