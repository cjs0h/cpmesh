<script lang="ts">
  import { onMount } from 'svelte';
  import { SvelteSet } from 'svelte/reactivity';
  import { push, replace, router } from 'svelte-spa-router';
  import { userState } from '../../lib/stores/user.svelte';
  import {
    auditActionGroup,
    auditActionLabel,
    auditActionTone,
    errorMessage,
    fetchAuditActions,
    fetchAuditLogs,
    isMfaRequired,
    type AuditLogRow,
  } from '../../lib/stores/admin.svelte';
  import { createClock } from '../../lib/clock.svelte';
  import { absoluteTime, relativeTime } from '../../lib/format';
  import Alert from '../../components/ui/Alert.svelte';
  import Badge from '../../components/ui/Badge.svelte';
  import Button from '../../components/ui/Button.svelte';
  import Card from '../../components/ui/Card.svelte';
  import EmptyState from '../../components/ui/EmptyState.svelte';
  import Field from '../../components/ui/Field.svelte';
  import Select from '../../components/ui/Select.svelte';
  import Skeleton from '../../components/ui/Skeleton.svelte';
  import AdminGate from '../../components/admin/AdminGate.svelte';
  import Pager from '../../components/admin/Pager.svelte';

  const LIMIT = 50;
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const clock = createClock();

  let action = $state('');
  let userFilter = $state('');
  let userError = $state('');
  let page = $state(1);
  let items = $state<AuditLogRow[]>([]);
  let total = $state(0);
  let actions = $state<string[]>([]);
  let loading = $state(false);
  let loaded = $state(false);
  let loadError = $state('');
  const expanded = new SvelteSet<string>();
  let request = 0;
  let active = true;

  onMount(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    const params = new URLSearchParams(router.querystring ?? '');
    userFilter = params.get('user') ?? '';
    action = params.get('action') ?? '';
    load();
    fetchAuditActions()
      .then((list) => (actions = list))
      .catch(() => {});
    return () => {
      active = false;
    };
  });

  const groups = $derived.by(() => {
    const byGroup = new Map<string, string[]>();
    for (const name of actions) {
      const group = auditActionGroup(name);
      byGroup.set(group, [...(byGroup.get(group) ?? []), name]);
    }
    return [...byGroup].map(([label, names]) => ({ label, names }));
  });

  const filtered = $derived(Boolean(action || userFilter.trim()));

  /** The filtered user's name, when an entry on this page mentions them. */
  const filterName = $derived.by(() => {
    const id = userFilter.trim().toLowerCase();
    if (!id) return null;
    for (const entry of items) {
      if (entry.user_id?.toLowerCase() === id && entry.username) return entry.username;
      if (entry.target_user_id?.toLowerCase() === id && entry.target_username) return entry.target_username;
    }
    return null;
  });

  async function load() {
    const user = userFilter.trim();
    if (user && !UUID.test(user)) {
      userError = 'Enter a complete user ID, or leave this empty.';
      return;
    }
    userError = '';
    const id = ++request;
    loading = true;
    try {
      const result = await fetchAuditLogs({ limit: LIMIT, offset: (page - 1) * LIMIT, user_id: user, action });
      if (id !== request || !active) return;
      items = result.items;
      total = result.total;
      expanded.clear();
      loaded = true;
      loadError = '';
      remember(user);
    } catch (err) {
      if (id === request && active && !isMfaRequired(err)) loadError = errorMessage(err);
    } finally {
      if (id === request) loading = false;
    }
  }

  function remember(user: string) {
    const params = new URLSearchParams();
    if (user) params.set('user', user);
    if (action) params.set('action', action);
    const search = params.toString();
    if (router.location === '/admin/audit' && (router.querystring ?? '') !== search) {
      replace(search ? `/admin/audit?${search}` : '/admin/audit');
    }
  }

  function applyFilters() {
    page = 1;
    load();
  }

  // Pasting a full ID filters right away; partial input waits for Enter
  function onUserInput() {
    const user = userFilter.trim();
    if (!user || UUID.test(user)) applyFilters();
  }

  function submitUser(e: SubmitEvent) {
    e.preventDefault();
    applyFilters();
  }

  function clearFilters() {
    action = '';
    userFilter = '';
    applyFilters();
  }

  function goTo(next: number) {
    page = next;
    load();
  }

  function toggle(id: string) {
    if (expanded.has(id)) expanded.delete(id);
    else expanded.add(id);
  }

  function hasDetails(entry: AuditLogRow): boolean {
    const { details } = entry;
    const empty = details === null || details === undefined || (typeof details === 'object' && Object.keys(details).length === 0);
    return !empty || Boolean(entry.user_agent);
  }
</script>

{#snippet person(id: string | null, name: string | null)}
  {#if id && name}
    <a href="#/admin/users/{id}" class="font-medium text-fg hover:underline">@{name}</a>
  {:else if id}
    <span class="text-dim" title={id}>Deleted user</span>
  {:else}
    <span class="text-dim">—</span>
  {/if}
{/snippet}

<AdminGate onunlock={load}>
  <div class="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-[260px_minmax(0,380px)_auto]">
    <Select bind:value={action} onchange={applyFilters} aria-label="Action">
      <option value="">All actions</option>
      {#each groups as group (group.label)}
        <optgroup label={group.label}>
          {#each group.names as name (name)}
            <option value={name}>{auditActionLabel(name)}</option>
          {/each}
        </optgroup>
      {/each}
    </Select>
    <form onsubmit={submitUser}>
      <Field icon="user" bind:value={userFilter} oninput={onUserInput} error={userError} placeholder="User ID" aria-label="User ID: entries by or about this user" />
    </form>
    {#if filtered}
      <div class="flex items-start">
        <Button variant="ghost" icon="x" onclick={clearFilters}>Clear filters</Button>
      </div>
    {/if}
  </div>

  {#if userFilter.trim() && !userError && filterName}
    <p class="mb-4 text-[13px] text-muted">
      Entries by or about <a href="#/admin/users/{userFilter.trim()}" class="font-medium text-fg hover:underline">@{filterName}</a>.
    </p>
  {/if}

  {#if loadError}
    <Alert tone="danger" title="Could not load the audit log" class="mb-4">
      {loadError}
      <Button variant="link" class="ml-1" onclick={load}>Try again</Button>
    </Alert>
  {/if}

  <Card padded={false}>
    {#if !loaded}
      <div class="flex flex-col gap-4 p-5" aria-busy="true">
        {#each Array(8) as _, i (i)}
          <div class="flex items-center gap-4"><Skeleton class="h-3 w-16" /><Skeleton class="h-3 w-24" /><Skeleton class="h-5 w-32" rounded="rounded-full" /><Skeleton class="h-3 w-24" /><Skeleton class="ml-auto h-3 w-20" /></div>
        {/each}
      </div>
    {:else if items.length === 0}
      <div class="p-5">
        {#if filtered}
          <EmptyState icon="filter" title="No matching entries" description="Nothing in the audit log matches these filters." compact>
            <Button variant="outline" size="sm" icon="x" onclick={clearFilters}>Clear filters</Button>
          </EmptyState>
        {:else}
          <EmptyState icon="activity" title="The audit log is empty" description="Sign-ins, security changes and every staff action are recorded here." compact />
        {/if}
      </div>
    {:else}
      <div class="overflow-x-auto">
        <table class="tbl min-w-[980px] {loading ? 'opacity-60' : ''}" aria-busy={loading}>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Target</th>
              <th>IP address</th>
              <th class="text-right">Details</th>
            </tr>
          </thead>
          <tbody>
            {#each items as entry (entry.id)}
              {@const open = expanded.has(entry.id)}
              <tr>
                <td class="whitespace-nowrap text-muted"><time datetime={entry.created_at} title={absoluteTime(entry.created_at)}>{relativeTime(entry.created_at, clock.now)}</time></td>
                <td>{@render person(entry.user_id, entry.username)}</td>
                <td><Badge tone={auditActionTone(entry.action)} title={entry.action}>{auditActionLabel(entry.action)}</Badge></td>
                <td>{#if entry.target_user_id}{@render person(entry.target_user_id, entry.target_username)}{:else}<span class="text-dim">—</span>{/if}</td>
                <td class="font-mono text-[12px] text-muted">{entry.ip_address || '—'}</td>
                <td class="text-right">
                  <span class="inline-flex h-7 items-center">
                    {#if hasDetails(entry)}
                      <Button variant="ghost" size="xs" iconRight={open ? 'chevron-down' : 'chevron-right'} aria-expanded={open} aria-controls="audit-{entry.id}" onclick={() => toggle(entry.id)}>
                        {open ? 'Hide' : 'Show'}
                      </Button>
                    {/if}
                  </span>
                </td>
              </tr>
              {#if open}
                <tr id="audit-{entry.id}" class="bg-bg-deep">
                  <td colspan="6" class="pt-0">
                    <pre class="max-h-72 overflow-auto rounded-md border border-border bg-surface p-3 font-mono text-[12px] leading-relaxed text-fg">{JSON.stringify(entry.details ?? {}, null, 2)}</pre>
                    {#if entry.user_agent}<p class="mt-2 break-all text-[12px] text-dim">User agent: {entry.user_agent}</p>{/if}
                  </td>
                </tr>
              {/if}
            {/each}
          </tbody>
        </table>
      </div>
      <Pager {page} perPage={LIMIT} {total} noun="entries" {loading} onpage={goTo} />
    {/if}
  </Card>
</AdminGate>
