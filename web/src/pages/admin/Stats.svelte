<script lang="ts">
  import { userState } from '../../lib/stores/user.svelte';
  import { adminState, fetchAdminStats } from '../../lib/stores/admin.svelte';
  import { push } from 'svelte-spa-router';

  let refreshInterval: ReturnType<typeof setInterval>;

  $effect(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    fetchAdminStats();
    refreshInterval = setInterval(fetchAdminStats, 10000);
    return () => clearInterval(refreshInterval);
  });
</script>

<div>
  <div class="flex items-center justify-between mb-6">
    <h2 class="text-xl font-semibold">System Stats</h2>
    <span class="text-muted text-[13px]">Auto-refreshes every 10s</span>
  </div>

  {#if adminState.stats}
    <div class="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-4">
      <div class="bg-bg-card border border-border rounded-lg p-6">
        <div class="text-[13px] text-muted mb-2">Total Users</div>
        <div class="text-4xl font-bold">{adminState.stats.total_users}</div>
      </div>
      <div class="bg-bg-card border border-border rounded-lg p-6">
        <div class="text-[13px] text-muted mb-2">Total Devices</div>
        <div class="text-4xl font-bold">{adminState.stats.total_devices}</div>
      </div>
      <div class="bg-bg-card border border-border rounded-lg p-6">
        <div class="text-[13px] text-muted mb-2">Clipboard Entries</div>
        <div class="text-4xl font-bold">{adminState.stats.total_entries}</div>
      </div>
      <div class="bg-bg-card border border-border rounded-lg p-6">
        <div class="text-[13px] text-muted mb-2">Active Connections</div>
        <div class="text-4xl font-bold text-success">{adminState.stats.active_connections}</div>
      </div>
    </div>
  {:else}
    <p class="text-muted text-[13px]">Loading stats...</p>
  {/if}
</div>
