<script lang="ts">
  import { onMount } from 'svelte';
  import { userState } from '../../lib/stores/user.svelte';
  import { adminState, fetchAdminStats } from '../../lib/stores/admin.svelte';
  import { createClock } from '../../lib/clock.svelte';
  import { relativeTime } from '../../lib/format';
  import { push } from 'svelte-spa-router';
  import StatCard from '../../components/ui/StatCard.svelte';
  import Badge from '../../components/ui/Badge.svelte';
  import Button from '../../components/ui/Button.svelte';
  import Skeleton from '../../components/ui/Skeleton.svelte';
  import Card from '../../components/ui/Card.svelte';
  import Icon from '../../components/Icon.svelte';

  const clock = createClock(5_000);
  let lastUpdated = $state<number | null>(null);
  let refreshing = $state(false);
  let history = $state<number[]>([]);

  async function refresh() {
    refreshing = true;
    await fetchAdminStats();
    refreshing = false;
    lastUpdated = Date.now();
    if (adminState.stats) history = [...history, adminState.stats.active_connections].slice(-16);
  }

  onMount(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    refresh();
    const id = setInterval(refresh, 10_000);
    return () => clearInterval(id);
  });

  const trend = $derived.by(() => {
    if (history.length < 3) return undefined;
    const max = Math.max(1, ...history);
    return history.map((v) => v / max);
  });

  const perUser = $derived.by(() => {
    const s = adminState.stats;
    if (!s || s.total_users === 0) return { devices: '0', entries: '0' };
    return { devices: (s.total_devices / s.total_users).toFixed(1), entries: Math.round(s.total_entries / s.total_users).toLocaleString() };
  });
</script>

<div class="mb-5 flex flex-wrap items-center justify-between gap-3">
  <div class="flex items-center gap-2 text-[12.5px] text-dim">
    <Badge tone="cyan" dot live>Auto-refresh · 10s</Badge>
    {#if lastUpdated}<span>Updated {relativeTime(lastUpdated, clock.now)}</span>{/if}
  </div>
  <Button variant="outline" size="sm" icon="refresh" loading={refreshing} onclick={refresh}>Refresh now</Button>
</div>

{#if adminState.stats}
  <div class="grid grid-cols-2 gap-4 xl:grid-cols-4">
    <StatCard label="Total users" value={adminState.stats.total_users.toLocaleString()} icon="users" accent="cyan" caption="registered accounts" />
    <StatCard label="Total devices" value={adminState.stats.total_devices.toLocaleString()} icon="monitor" accent="violet" caption="{perUser.devices} per user on average" delay={60} />
    <StatCard label="Clipboard entries" value={adminState.stats.total_entries.toLocaleString()} icon="clipboard" accent="accent" caption="{perUser.entries} per user on average" delay={120} />
    <StatCard label="Active connections" value={adminState.stats.active_connections.toLocaleString()} icon="radio" accent="mint" caption="live WebSocket sessions" {trend} delay={180} />
  </div>

  <div class="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
    <Card title="Relay health" description="What this instance is doing right now" icon="activity" accent="mint">
      <ul class="flex flex-col divide-y divide-border text-sm">
        <li class="flex items-center justify-between py-2.5"><span class="text-muted">Connections per device</span><span class="font-mono text-fg">{adminState.stats.total_devices ? (adminState.stats.active_connections / adminState.stats.total_devices * 100).toFixed(0) : 0}% online</span></li>
        <li class="flex items-center justify-between py-2.5"><span class="text-muted">Entries stored</span><span class="font-mono text-fg">{adminState.stats.total_entries.toLocaleString()}</span></li>
        <li class="flex items-center justify-between py-2.5"><span class="text-muted">Content visibility</span><span class="inline-flex items-center gap-1.5 font-mono text-success"><Icon name="lock" size={12} /> ciphertext only</span></li>
      </ul>
    </Card>
    <Card title="Shortcuts" description="Common administration tasks" icon="sparkles" accent="gold">
      <div class="grid grid-cols-1 gap-2 sm:grid-cols-2">
        <Button variant="outline" size="sm" icon="users" href="#/admin/users" class="justify-start">Review users</Button>
        <Button variant="outline" size="sm" icon="star" href="#/admin/plans" class="justify-start">Edit plans</Button>
        <Button variant="outline" size="sm" icon="upload" href="#/admin/releases" class="justify-start">Publish a release</Button>
        <Button variant="outline" size="sm" icon="sliders" href="#/admin/settings" class="justify-start">Test SMTP / OIDC</Button>
      </div>
    </Card>
  </div>
{:else}
  <div class="grid grid-cols-2 gap-4 xl:grid-cols-4">
    {#each Array(4) as _, i (i)}
      <div class="rounded-lg border border-border bg-surface p-5"><Skeleton class="mb-3 h-3 w-1/2" /><Skeleton class="h-8 w-1/3" /></div>
    {/each}
  </div>
{/if}
