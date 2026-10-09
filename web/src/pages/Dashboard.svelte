<script lang="ts">
  import { onMount } from 'svelte';
  import { devicesState, fetchDevices } from '../lib/stores/devices.svelte';
  import { clipboardState, fetchClipboard } from '../lib/stores/clipboard.svelte';
  import { userState } from '../lib/stores/user.svelte';
  import { connectionState } from '../lib/stores/connection.svelte';
  import { createClock } from '../lib/clock.svelte';
  import { absoluteTime, base64Size, contentTypeMeta, formatBytes, greeting, relativeTime } from '../lib/format';
  import Icon from '../components/Icon.svelte';
  import StatCard from '../components/ui/StatCard.svelte';
  import Card from '../components/ui/Card.svelte';
  import Badge from '../components/ui/Badge.svelte';
  import Button from '../components/ui/Button.svelte';
  import EmptyState from '../components/ui/EmptyState.svelte';
  import Skeleton from '../components/ui/Skeleton.svelte';
  import IconTile from '../components/ui/IconTile.svelte';
  import DownloadButtons from '../components/ui/DownloadButtons.svelte';

  const clock = createClock();
  let initialLoad = $state(true);

  onMount(() => {
    Promise.all([fetchDevices(), fetchClipboard(true)]).finally(() => (initialLoad = false));
  });

  const firstName = $derived((userState.fullName || userState.username || '').split(' ')[0]);
  const onlineCount = $derived(devicesState.list.filter((d) => d.online).length);
  const approvedDevices = $derived(devicesState.list.filter((d) => d.status === 'approved' || !d.status));
  const pendingDevices = $derived(devicesState.list.filter((d) => d.status === 'pending'));
  const recent = $derived(clipboardState.entries.slice(0, 8));
  const latest = $derived(clipboardState.entries[0]);
  const entryCount = $derived(`${clipboardState.entries.length}${clipboardState.hasMore ? '+' : ''}`);
  // Activity histogram for the last 12 hours, derived from the loaded page.
  const activityTrend = $derived.by(() => {
    const buckets = new Array(12).fill(0);
    const now = clock.now;
    for (const e of clipboardState.entries) {
      const age = now - new Date(e.created_at).getTime();
      const idx = 11 - Math.floor(age / 3_600_000);
      if (idx >= 0 && idx < 12) buckets[idx]++;
    }
    const max = Math.max(1, ...buckets);
    return buckets.map((b) => b / max);
  });
</script>

<!-- Greeting -->
<div class="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
  <div>
    <p class="inline-block rounded-sm border-2 border-ink bg-yellow px-2 py-0.5 font-head text-[10.5px] uppercase tracking-[0.14em] text-ink shadow-xs">Overview</p>
    <h1 class="mt-3 font-head text-2xl text-ink sm:text-[30px]">
      {greeting()}{firstName ? `, ${firstName}` : ''}
    </h1>
    <p class="mt-1 text-sm text-muted">
      {#if connectionState.status === 'online'}
        Live sync is on — new clips appear here the moment you copy them.
      {:else}
        Everything you copy is encrypted before it leaves your devices.
      {/if}
    </p>
  </div>
  <div class="flex items-center gap-2">
    <Button variant="outline" size="sm" icon="monitor" href="#/devices">Manage devices</Button>
    <Button variant="secondary" size="sm" icon="history" href="#/clipboard">Full history</Button>
  </div>
</div>

<!-- Stats -->
<div class="grid grid-cols-2 gap-4 xl:grid-cols-4">
  <StatCard label="Devices" value={devicesState.list.length} icon="monitor" accent="cyan" caption={pendingDevices.length ? `${pendingDevices.length} awaiting approval` : 'paired to your account'} />
  <StatCard label="Online now" value={onlineCount} icon="wifi" accent="mint" caption={onlineCount ? 'connected to the relay' : 'no live connections'} delay={60} />
  <StatCard label="Clipboard entries" value={entryCount} icon="clipboard" accent="accent" caption="encrypted at rest" trend={activityTrend} delay={120} />
  <StatCard label="Last activity" value={latest ? relativeTime(latest.created_at, clock.now) : '—'} icon="activity" accent="gold" caption={latest ? `from ${latest.device_name || 'a device'}` : 'nothing copied yet'} delay={180} />
</div>

<div class="mt-6 grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
  <!-- Recent activity -->
  <Card title="Recent activity" description="Newest clips across all your devices" icon="activity" accent="accent" padded={false}>
    {#snippet actions()}
      {#if connectionState.status === 'online'}
        <Badge tone="mint" dot live>Live</Badge>
      {/if}
    {/snippet}

    {#if initialLoad && clipboardState.loading}
      <div class="flex flex-col gap-3 p-5">
        {#each Array(4) as _, i (i)}
          <div class="flex items-center gap-3">
            <Skeleton class="h-9 w-9" rounded="rounded-lg" />
            <div class="flex-1"><Skeleton class="mb-2 h-3 w-1/3" /><Skeleton class="h-3 w-1/5" /></div>
            <Skeleton class="h-3 w-12" />
          </div>
        {/each}
      </div>
    {:else if recent.length === 0}
      <div class="p-5">
        <EmptyState icon="clipboard" title="Nothing copied yet" description="Copy something on any paired device and it will show up here within a second — encrypted end to end." compact />
      </div>
    {:else}
      <ul class="divide-y-2 divide-ink/10">
        {#each recent as entry (entry.id)}
          {@const meta = contentTypeMeta(entry.content_type)}
          <li class="flex items-center gap-3.5 px-5 py-3 transition-colors hover:bg-surface-2 animate-[fade-up_0.35s_var(--ease-out-expo)]">
            <IconTile icon={meta.icon} tone={meta.tone} title={meta.label} />
            <div class="min-w-0 flex-1">
              <p class="truncate text-sm font-medium text-fg">{meta.label} from {entry.device_name || 'unknown device'}</p>
              <p class="mt-0.5 flex items-center gap-2 text-[12px] text-dim">
                <span class="font-mono">{formatBytes(base64Size(entry.encrypted_data))}</span>
                <span aria-hidden="true">·</span>
                <span class="inline-flex items-center gap-1"><Icon name="lock" size={10} /> encrypted</span>
              </p>
            </div>
            <time class="shrink-0 text-[12px] text-muted" datetime={entry.created_at} title={absoluteTime(entry.created_at)}>
              {relativeTime(entry.created_at, clock.now)}
            </time>
          </li>
        {/each}
      </ul>
      <div class="border-t-2 border-ink/10 bg-surface-2/60 px-5 py-3 text-right">
        <a href="#/clipboard" class="inline-flex items-center gap-1 font-head text-[11px] uppercase tracking-[0.08em] text-ink underline decoration-2 decoration-yellow underline-offset-4 hover:decoration-ink">
          View full history <Icon name="arrow-right" size={13} />
        </a>
      </div>
    {/if}
  </Card>

  <div class="flex flex-col gap-6">
    <!-- Devices -->
    <Card title="Devices" description="{onlineCount} of {devicesState.list.length} online" icon="monitor" accent="cyan" padded={false}>
      {#snippet actions()}
        <a href="#/devices" class="text-[12px] font-medium text-muted hover:text-fg">Manage</a>
      {/snippet}

      {#if devicesState.list.length === 0 && !devicesState.loading}
        <div class="p-5">
          <EmptyState icon="smartphone" title="No devices yet" description="Install the cpmesh app and sign in to pair your first device." compact>
            <DownloadButtons />
          </EmptyState>
        </div>
      {:else}
        <ul class="divide-y-2 divide-ink/10">
          {#each devicesState.list.slice(0, 6) as device (device.id)}
            <li class="flex items-center gap-3 px-5 py-3">
              <span class="flex h-8 w-8 items-center justify-center rounded border-2 border-ink text-ink shadow-xs {device.online ? 'bg-mint' : 'bg-surface-2'}"><Icon name="monitor" size={15} strokeWidth={2.4} /></span>
              <div class="min-w-0 flex-1">
                <p class="truncate text-sm font-medium text-fg">{device.name}</p>
                <p class="text-[12px] text-dim">
                  {#if device.status === 'pending'}Awaiting approval{:else if device.online}Connected now{:else if device.last_seen}Seen {relativeTime(device.last_seen, clock.now)}{:else}Never connected{/if}
                </p>
              </div>
              {#if device.status === 'pending'}
                <Badge tone="gold">Pending</Badge>
              {:else}
                <span class="status-dot {device.online ? 'text-mint' : 'text-dim'}" data-live={device.online}></span>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    </Card>

    <!-- Security note -->
    <div class="panel p-5" style="--panel-shadow: var(--color-mint);">
      <div class="flex items-start gap-3">
        <span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border-2 border-ink bg-mint text-ink shadow-xs"><Icon name="shield-check" size={17} strokeWidth={2.4} /></span>
        <div>
          <p class="font-head text-[15px] text-ink">Zero-knowledge relay</p>
          <p class="mt-1 text-[13px] leading-relaxed text-muted">
            This dashboard lists <em>what</em> was synced — never the contents. Clips are sealed with AES-256-GCM on your device, and only your paired devices hold the keys.
          </p>
        </div>
      </div>
      <dl class="mt-4 grid grid-cols-3 gap-2 text-center">
        {#each [
          ['Cipher', 'AES-256'],
          ['Key exchange', 'ECDH P-256'],
          ['Relay sees', 'Ciphertext'],
        ] as [k, v] (k)}
          <div class="rounded-md border-2 border-ink bg-surface-2 px-2 py-2 shadow-xs">
            <dt class="font-head text-[9.5px] uppercase tracking-[0.1em] text-muted">{k}</dt>
            <dd class="mt-0.5 font-mono text-[11.5px] font-semibold text-ink">{v}</dd>
          </div>
        {/each}
      </dl>
    </div>
  </div>
</div>
