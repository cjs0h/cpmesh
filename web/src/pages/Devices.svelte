<script lang="ts">
  import { devicesState, fetchDevices, updateDeviceStatus } from '../lib/stores/devices.svelte';
  import { onWSMessage } from '../lib/ws';
  import { api } from '../lib/api';
  import Icon from '../components/Icon.svelte';

  let deleteConfirm = $state<string | null>(null);

  $effect(() => {
    fetchDevices();
    const unsub = onWSMessage((msg) => {
      if (msg.type === 'device_status') {
        updateDeviceStatus(msg.payload.device_id, msg.payload.online);
      }
    });
    return unsub;
  });

  async function handleDelete(id: string) {
    await api(`/api/devices/${id}`, { method: 'DELETE' });
    devicesState.list = devicesState.list.filter((d) => d.id !== id);
    deleteConfirm = null;
  }
</script>

<div>
  {#if devicesState.loading}
    <div class="flex items-center gap-2.5 p-6 text-muted">
      <span class="inline-block w-4 h-4 border-2 border-border border-t-primary rounded-full animate-[spin_0.6s_linear_infinite]"></span>
      <span>Loading...</span>
    </div>
  {:else if devicesState.list.length === 0}
    <div class="text-center py-15 px-4 bg-bg-card border border-border rounded-xl">
      <div class="text-dim mb-4"><Icon name="monitor" size={32} /></div>
      <p class="mb-1 font-medium">No devices registered.</p>
      <p class="text-muted text-[13px]">Connect a device using the cpmesh client to see it here.</p>
    </div>
  {:else}
    <div class="grid grid-cols-[repeat(auto-fill,minmax(300px,1fr))] gap-4">
      {#each devicesState.list as device}
        <div class="bg-bg-card border rounded-xl p-[22px] transition-all duration-200 hover:border-border-hover hover:shadow-md {device.online ? 'border-success/20' : 'border-border'}">
          <div class="flex items-center gap-2.5 mb-3">
            <div class="w-[34px] h-[34px] rounded bg-primary-glow border border-primary/15 text-primary flex items-center justify-center shrink-0">
              <Icon name="monitor" size={18} />
            </div>
            <span class="font-semibold text-[15px] flex-1">{device.name}</span>
            <div class="flex items-center gap-2">
              {#if device.status === 'pending'}
                <span class="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-yellow-500/15 text-yellow-400 border border-yellow-500/20">Pending</span>
              {:else if device.status === 'rejected'}
                <span class="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-red-500/15 text-red-400 border border-red-500/20">Rejected</span>
              {:else if device.status === 'revoked'}
                <span class="text-[11px] font-semibold px-2 py-0.5 rounded-full bg-red-500/15 text-red-400 border border-red-500/20">Revoked</span>
              {:else}
                <div class="flex items-center gap-1.5">
                  <span class="w-2 h-2 rounded-full {device.online ? 'bg-success shadow-[0_0_8px_rgba(52,211,153,0.5)]' : 'bg-text-dim'}"></span>
                  <span class="text-xs font-medium {device.online ? 'text-success' : 'text-muted'}">{device.online ? 'Online' : 'Offline'}</span>
                </div>
              {/if}
            </div>
          </div>
          {#if device.status === 'pending'}
            <div class="text-xs text-yellow-400/80 bg-yellow-500/10 rounded px-2.5 py-2 mb-2 border border-yellow-500/15">
              <p class="mb-1 font-medium">Waiting for approval</p>
              <p>Open the <strong>cpmesh desktop app</strong> on an already-approved device, go to <strong>Devices</strong>, and tap <strong>Approve</strong> next to this device.</p>
            </div>
          {/if}
          {#if device.last_seen}
            <div class="flex items-center gap-1.5 text-xs text-muted mb-2">
              <Icon name="clock" size={12} />
              <span>Last seen: {new Date(device.last_seen).toLocaleString()}</span>
            </div>
          {/if}
          <div class="text-[11px] font-mono text-dim break-all mb-3.5 px-2.5 py-1.5 bg-bg-input rounded-sm border border-border">{device.id}</div>
          <div class="flex items-center gap-2">
            {#if deleteConfirm === device.id}
              <span class="text-[13px] text-warning font-medium">Remove device?</span>
              <button class="inline-flex items-center gap-[5px] border-none rounded text-[13px] font-medium py-[7px] px-3.5 transition-all duration-150 bg-danger text-white hover:bg-danger-hover" onclick={() => handleDelete(device.id)}>Yes</button>
              <button class="inline-flex items-center gap-[5px] border border-border rounded text-[13px] font-medium py-[7px] px-3.5 transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => (deleteConfirm = null)}>No</button>
            {:else}
              <button class="inline-flex items-center gap-[5px] border border-border rounded text-[13px] font-medium py-[7px] px-3.5 transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => (deleteConfirm = device.id)}>
                <Icon name="trash" size={13} /> Remove
              </button>
            {/if}
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>
