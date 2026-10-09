<script lang="ts">
  import { onMount } from 'svelte';
  import { devicesState, fetchDevices } from '../lib/stores/devices.svelte';
  import { toast } from '../lib/stores/toast.svelte';
  import { api } from '../lib/api';
  import { createClock } from '../lib/clock.svelte';
  import { absoluteTime, relativeTime, truncateMiddle } from '../lib/format';
  import Icon from '../components/Icon.svelte';
  import Badge from '../components/ui/Badge.svelte';
  import Button from '../components/ui/Button.svelte';
  import ConfirmAction from '../components/ui/ConfirmAction.svelte';
  import EmptyState from '../components/ui/EmptyState.svelte';
  import Skeleton from '../components/ui/Skeleton.svelte';
  import CopyButton from '../components/ui/CopyButton.svelte';
  import Alert from '../components/ui/Alert.svelte';
  import DownloadButtons from '../components/ui/DownloadButtons.svelte';

  const clock = createClock();

  onMount(() => {
    fetchDevices();
  });

  const online = $derived(devicesState.list.filter((d) => d.online).length);
  const pending = $derived(devicesState.list.filter((d) => d.status === 'pending'));
  const sorted = $derived(
    [...devicesState.list].sort((a, b) => {
      const rank = (d: typeof a) => (d.status === 'pending' ? 0 : d.online ? 1 : 2);
      return rank(a) - rank(b) || a.name.localeCompare(b.name);
    })
  );

  async function handleDelete(id: string, name: string) {
    try {
      await api(`/api/devices/${id}`, { method: 'DELETE' });
      devicesState.list = devicesState.list.filter((d) => d.id !== id);
      toast.success('Device removed', `${name} can no longer sync with your account.`);
    } catch (err: any) {
      toast.error('Could not remove device', err.message);
    }
  }

  function statusOf(d: (typeof devicesState.list)[number]): { tone: 'mint' | 'gold' | 'rose' | 'neutral'; label: string; live: boolean } {
    if (d.status === 'pending') return { tone: 'gold', label: 'Pending approval', live: false };
    if (d.status === 'rejected') return { tone: 'rose', label: 'Rejected', live: false };
    if (d.status === 'revoked') return { tone: 'rose', label: 'Revoked', live: false };
    return d.online ? { tone: 'mint', label: 'Online', live: true } : { tone: 'neutral', label: 'Offline', live: false };
  }
</script>

<div class="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
  <div class="flex flex-wrap items-center gap-2 text-[13px] text-muted">
    <Badge tone="mint" dot live={online > 0}>{online} online</Badge>
    <Badge tone="neutral">{devicesState.list.length} total</Badge>
    {#if pending.length}<Badge tone="gold" icon="clock">{pending.length} pending</Badge>{/if}
  </div>
  <Button variant="outline" size="sm" icon="refresh" loading={devicesState.loading} onclick={fetchDevices}>Refresh</Button>
</div>

{#if pending.length > 0}
  <Alert tone="warning" title="A device is waiting for approval" class="mb-5">
    Open the <strong class="text-fg">cpmesh desktop app</strong> on an already-approved device, go to <strong class="text-fg">Devices</strong> and tap
    <strong class="text-fg">Approve</strong>. Approval exchanges encryption keys directly between your devices — the relay never sees them.
  </Alert>
{/if}

{#if devicesState.loading && devicesState.list.length === 0}
  <div class="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
    {#each Array(3) as _, i (i)}
      <div class="rounded-lg border border-border bg-surface p-5">
        <div class="flex items-center gap-3"><Skeleton class="h-10 w-10" rounded="rounded-md" /><div class="flex-1"><Skeleton class="mb-2 h-3.5 w-1/2" /><Skeleton class="h-3 w-1/3" /></div></div>
        <Skeleton class="mt-5 h-8 w-full" />
      </div>
    {/each}
  </div>
{:else if devicesState.list.length === 0}
  <EmptyState icon="smartphone" title="No devices paired yet" description="Install cpmesh on your laptop, desktop or phone and sign in. The first device is approved automatically; every additional one is approved from an existing device.">
    <DownloadButtons size="sm" />
  </EmptyState>
{:else}
  <div class="grid grid-cols-1 gap-5 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
    {#each sorted as device (device.id)}
      {@const s = statusOf(device)}
      <article class="group relative flex flex-col rounded-lg border border-border bg-surface p-5 transition-[border-color,box-shadow] duration-150 hover:border-border-strong hover:shadow-sm">
        <div class="relative flex items-start gap-3">
          <span class="flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-border bg-surface-2 {device.online ? 'text-fg' : 'text-dim'}">
            <Icon name="monitor" size={18} />
          </span>
          <div class="min-w-0 flex-1">
            <h3 class="truncate text-sm font-medium text-fg">{device.name}</h3>
            <p class="mt-0.5 flex items-center gap-1.5 text-[12.5px] text-dim">
              <Icon name="clock" size={11} />
              {#if device.online}
                Connected now
              {:else if device.last_seen}
                <time datetime={device.last_seen} title={absoluteTime(device.last_seen)}>Last seen {relativeTime(device.last_seen, clock.now)}</time>
              {:else}
                Never connected
              {/if}
            </p>
          </div>
          <Badge tone={s.tone} dot={s.tone === 'mint' || s.tone === 'neutral'} live={s.live}>{s.label}</Badge>
        </div>

        <div class="relative mt-4 flex items-center justify-between gap-2 rounded-md border border-border bg-bg-deep px-3 py-2">
          <span class="text-xs text-muted">Device ID</span>
          <span class="flex items-center gap-1">
            <code class="font-mono text-[11.5px] text-fg">{truncateMiddle(device.id, 8)}</code>
            <CopyButton text={device.id} label="Copy device ID" size={12} />
          </span>
        </div>

        <div class="relative mt-4 flex items-center justify-between">
          <span class="inline-flex items-center gap-1.5 text-xs text-dim">
            <Icon name="shield-check" size={13} />
            E2E keys held on device
          </span>
          <ConfirmAction label="Remove" confirmLabel="Remove" prompt="Remove this device?" size="xs" onconfirm={() => handleDelete(device.id, device.name)} />
        </div>
      </article>
    {/each}
  </div>
{/if}
