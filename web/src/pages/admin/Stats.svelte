<script lang="ts">
  import { onMount } from 'svelte';
  import { push } from 'svelte-spa-router';
  import { userState } from '../../lib/stores/user.svelte';
  import { adminGate, adminState, errorMessage, fetchAdminStats, isMfaRequired, type DailyCount } from '../../lib/stores/admin.svelte';
  import { createClock } from '../../lib/clock.svelte';
  import { formatBytes, relativeTime } from '../../lib/format';
  import Icon from '../../components/Icon.svelte';
  import Alert from '../../components/ui/Alert.svelte';
  import Badge from '../../components/ui/Badge.svelte';
  import Button from '../../components/ui/Button.svelte';
  import Card from '../../components/ui/Card.svelte';
  import Skeleton from '../../components/ui/Skeleton.svelte';
  import StatCard from '../../components/ui/StatCard.svelte';
  import AdminGate from '../../components/admin/AdminGate.svelte';
  import TrendChart from '../../components/admin/TrendChart.svelte';

  const REFRESH_MS = 10_000;
  const clock = createClock(5_000);
  let lastUpdated = $state<number | null>(null);
  let refreshing = $state(false);
  let refreshError = $state('');
  let history = $state<number[]>([]);

  async function refresh() {
    refreshing = true;
    try {
      const stats = await fetchAdminStats();
      lastUpdated = Date.now();
      refreshError = '';
      history = [...history, stats.active_connections].slice(-16);
    } catch (err) {
      if (!isMfaRequired(err)) refreshError = errorMessage(err);
    } finally {
      refreshing = false;
    }
  }

  onMount(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    refresh();
    const id = setInterval(() => {
      if (!adminGate.required && !refreshing) refresh();
    }, REFRESH_MS);
    return () => clearInterval(id);
  });

  const stats = $derived(adminState.stats);

  function percent(part: number, whole: number): number {
    return whole > 0 ? Math.round((part / whole) * 100) : 0;
  }

  function total(series: DailyCount[]): number {
    return series.reduce((sum, p) => sum + p.count, 0);
  }

  const trend = $derived.by(() => {
    if (history.length < 3) return undefined;
    const max = Math.max(1, ...history);
    return history.map((v) => v / max);
  });

  const perUser = $derived.by(() => {
    if (!stats || stats.total_users === 0) return { devices: '0', entries: '0' };
    return { devices: (stats.total_devices / stats.total_users).toFixed(1), entries: Math.round(stats.total_entries / stats.total_users).toLocaleString() };
  });

  const counters = $derived.by(() => {
    if (!stats) return [];
    const users = stats.total_users;
    return [
      { label: 'Active today', icon: 'activity', value: stats.active_users_1d.toLocaleString(), caption: `${percent(stats.active_users_1d, users)}% of accounts` },
      { label: 'Active, 7 days', icon: 'calendar', value: stats.active_users_7d.toLocaleString(), caption: `${percent(stats.active_users_7d, users)}% of accounts` },
      { label: 'Active, 30 days', icon: 'calendar', value: stats.active_users_30d.toLocaleString(), caption: `${percent(stats.active_users_30d, users)}% of accounts` },
      { label: '2FA adoption', icon: 'shield-check', value: `${percent(stats.mfa_users, users)}%`, caption: `${stats.mfa_users.toLocaleString()} of ${users.toLocaleString()} accounts`, href: '#/admin/users?status=no_mfa', hrefLabel: 'Show accounts without 2FA' },
      { label: 'Suspended', icon: 'lock', value: stats.suspended_users.toLocaleString(), caption: 'blocked from signing in', href: '#/admin/users?status=suspended', hrefLabel: 'Show suspended accounts' },
      { label: 'Pending devices', icon: 'clock', value: stats.pending_devices.toLocaleString(), caption: 'awaiting approval' },
      { label: 'Staff', icon: 'shield', value: stats.staff_users.toLocaleString(), caption: 'viewers, support, admins, owners', href: '#/admin/users?role=staff', hrefLabel: 'Show staff accounts' },
      { label: 'Storage', icon: 'hard-drive', value: formatBytes(stats.storage_bytes), caption: 'encrypted clipboard data' },
    ];
  });

  const planUsers = $derived(stats ? stats.plans.reduce((sum, p) => sum + p.users, 0) : 0);
</script>

{#snippet seriesTotal(value: number, label: string)}
  <p class="text-right leading-tight">
    <span class="block text-base font-semibold tracking-tight text-fg tabular-nums">{value.toLocaleString()}</span>
    <span class="text-[11px] text-dim">{label}</span>
  </p>
{/snippet}

<AdminGate onunlock={refresh}>
  <div class="mb-5 flex flex-wrap items-center justify-between gap-3">
    <div class="flex flex-wrap items-center gap-2 text-[12.5px] text-dim">
      <Badge tone="cyan" dot live>Auto-refresh · 10s</Badge>
      {#if refreshError && stats}
        <span class="text-danger">Refresh failed: {refreshError}</span>
      {:else if lastUpdated}
        <span>Updated {relativeTime(lastUpdated, clock.now)}</span>
      {/if}
    </div>
    <Button variant="outline" size="sm" icon="refresh" loading={refreshing} onclick={refresh}>Refresh now</Button>
  </div>

  {#if stats}
    <div class="grid grid-cols-2 gap-4 xl:grid-cols-4">
      <StatCard label="Users" value={stats.total_users.toLocaleString()} icon="users" caption="{total(stats.signups).toLocaleString()} joined in the last 30 days" />
      <StatCard label="Devices" value={stats.total_devices.toLocaleString()} icon="monitor" caption="{perUser.devices} per user on average" />
      <StatCard label="Clipboard entries" value={stats.total_entries.toLocaleString()} icon="clipboard" caption="{perUser.entries} per user on average" />
      <StatCard label="Live connections" value={stats.active_connections.toLocaleString()} icon="radio" caption="WebSocket sessions right now" {trend} />
    </div>

    <div class="cell-grid mt-4 grid-cols-2 overflow-hidden rounded-lg bg-surface md:grid-cols-4">
      {#each counters as c (c.label)}
        {#if c.href}
          <a href={c.href} class="group block px-5 py-4 transition-colors duration-150 hover:bg-bg-deep" title={c.hrefLabel}>
            <p class="flex items-center gap-1.5 text-[12.5px] text-muted"><Icon name={c.icon} size={13} />{c.label}</p>
            <p class="mt-1.5 text-xl font-semibold tracking-tight text-fg tabular-nums">{c.value}</p>
            <p class="mt-0.5 flex items-center gap-1 text-xs text-dim group-hover:text-fg">{c.caption}<Icon name="arrow-right" size={11} /></p>
          </a>
        {:else}
          <div class="px-5 py-4">
            <p class="flex items-center gap-1.5 text-[12.5px] text-muted"><Icon name={c.icon} size={13} />{c.label}</p>
            <p class="mt-1.5 text-xl font-semibold tracking-tight text-fg tabular-nums">{c.value}</p>
            <p class="mt-0.5 text-xs text-dim">{c.caption}</p>
          </div>
        {/if}
      {/each}
    </div>

    <div class="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
      <Card title="Signups" description="New accounts per day" icon="user-plus">
        {#snippet actions()}{@render seriesTotal(total(stats.signups), 'last 30 days')}{/snippet}
        <TrendChart series={stats.signups} unit="signups" />
      </Card>
      <Card title="Daily active users" description="Accounts that used cpmesh each day" icon="activity">
        {#snippet actions()}{@render seriesTotal(stats.active_users.at(-1)?.count ?? 0, 'today')}{/snippet}
        <TrendChart series={stats.active_users} unit="active users" />
      </Card>
      <Card title="Clipboard entries" description="Entries synced per day" icon="clipboard">
        {#snippet actions()}{@render seriesTotal(total(stats.entries), 'last 30 days')}{/snippet}
        <TrendChart series={stats.entries} unit="entries" />
      </Card>
    </div>

    <div class="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
      <Card title="Plans" description="How accounts are spread across plans" icon="star">
        {#if stats.plans.length === 0}
          <p class="text-[13px] text-muted">No accounts yet.</p>
        {:else}
          <ul class="flex flex-col gap-3.5">
            {#each stats.plans as plan (plan.plan_id ?? 'none')}
              {@const share = percent(plan.users, planUsers)}
              <li>
                <div class="flex items-baseline justify-between gap-3 text-[13px]">
                  {#if plan.plan_id}
                    <a href="#/admin/users?plan_id={plan.plan_id}" class="truncate font-medium text-fg hover:underline">{plan.name}</a>
                  {:else}
                    <span class="truncate font-medium text-muted">{plan.name}</span>
                  {/if}
                  <span class="shrink-0 font-mono text-[12px] text-muted tabular-nums">{plan.users.toLocaleString()} · {share}%</span>
                </div>
                <div class="mt-1.5 h-1.5 overflow-hidden rounded-full bg-surface-2" aria-hidden="true">
                  <div class="h-full rounded-full bg-ink" style="width: {plan.users > 0 ? Math.max(share, 1) : 0}%"></div>
                </div>
              </li>
            {/each}
          </ul>
        {/if}
      </Card>
      <Card title="Shortcuts" description="Common administration tasks" icon="sparkles">
        <div class="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <Button variant="outline" size="sm" icon="users" href="#/admin/users" class="justify-start">Review users</Button>
          <Button variant="outline" size="sm" icon="activity" href="#/admin/audit" class="justify-start">Audit log</Button>
          <Button variant="outline" size="sm" icon="upload" href="#/admin/releases" class="justify-start">Publish a release</Button>
          <Button variant="outline" size="sm" icon="sliders" href="#/admin/settings" class="justify-start">Site settings</Button>
        </div>
      </Card>
    </div>
  {:else if refreshError}
    <Alert tone="danger" title="Could not load the statistics">
      {refreshError}
      <Button variant="link" class="ml-1" onclick={refresh}>Try again</Button>
    </Alert>
  {:else}
    <div class="grid grid-cols-2 gap-4 xl:grid-cols-4" aria-busy="true">
      {#each Array(4) as _, i (i)}
        <div class="rounded-lg border border-border bg-surface p-5"><Skeleton class="mb-3 h-3 w-1/2" /><Skeleton class="h-8 w-1/3" /></div>
      {/each}
    </div>
    <div class="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-3">
      {#each Array(3) as _, i (i)}
        <div class="rounded-lg border border-border bg-surface p-5"><Skeleton class="mb-4 h-3.5 w-1/3" /><Skeleton class="h-16 w-full" /></div>
      {/each}
    </div>
  {/if}
</AdminGate>
