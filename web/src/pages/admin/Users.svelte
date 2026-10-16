<script lang="ts">
  import { onMount, untrack } from 'svelte';
  import { push, replace, router } from 'svelte-spa-router';
  import { userState } from '../../lib/stores/user.svelte';
  import {
    adminState,
    errorMessage,
    fetchAdminPlans,
    fetchAdminUsers,
    isMfaRequired,
    ROLES,
    USER_STATUSES,
    type AdminUserQuery,
  } from '../../lib/stores/admin.svelte';
  import { createClock } from '../../lib/clock.svelte';
  import { absoluteTime, relativeTime } from '../../lib/format';
  import Icon from '../../components/Icon.svelte';
  import Alert from '../../components/ui/Alert.svelte';
  import Avatar from '../../components/ui/Avatar.svelte';
  import Badge from '../../components/ui/Badge.svelte';
  import Button from '../../components/ui/Button.svelte';
  import Card from '../../components/ui/Card.svelte';
  import EmptyState from '../../components/ui/EmptyState.svelte';
  import Field from '../../components/ui/Field.svelte';
  import Select from '../../components/ui/Select.svelte';
  import Skeleton from '../../components/ui/Skeleton.svelte';
  import AdminGate from '../../components/admin/AdminGate.svelte';
  import Pager from '../../components/admin/Pager.svelte';
  import RoleBadge from '../../components/admin/RoleBadge.svelte';
  import { rowLink } from '../../components/admin/rowLink';

  const PER_PAGE = 25;
  const SEARCH_DELAY_MS = 300;
  const clock = createClock();

  let q = $state('');
  let role = $state('');
  let status = $state('');
  let planId = $state('');
  let page = $state(1);
  let loaded = $state(false);
  let loadError = $state('');
  let searchTimer: ReturnType<typeof setTimeout> | undefined;
  let active = true;
  let mounted = $state(false);
  /** The address this page last read or wrote, to tell its own updates from navigation. */
  let syncedQuery = '';

  // Filters live in the address, so links (and going back) can open a filtered list
  function readFilters(querystring: string) {
    const params = new URLSearchParams(querystring);
    q = params.get('q') ?? '';
    role = params.get('role') ?? '';
    status = params.get('status') ?? '';
    planId = params.get('plan_id') ?? '';
    page = Math.max(1, Number.parseInt(params.get('page') ?? '', 10) || 1);
    syncedQuery = querystring;
  }

  onMount(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    readFilters(router.querystring ?? '');
    mounted = true;
    load();
    fetchAdminPlans().catch(() => {});
    return () => {
      active = false;
      clearTimeout(searchTimer);
    };
  });

  // A link to another filtered list (or the plain list) while this page is open
  $effect(() => {
    const querystring = router.querystring ?? '';
    if (!mounted || router.location !== '/admin/users' || querystring === syncedQuery) return;
    untrack(() => {
      readFilters(querystring);
      load();
    });
  });

  const filtered = $derived(Boolean(q.trim() || role || status || planId));

  function currentQuery(): AdminUserQuery {
    return {
      q: q.trim(),
      role: role as AdminUserQuery['role'],
      status: status as AdminUserQuery['status'],
      plan_id: planId,
      page,
    };
  }

  async function load() {
    clearTimeout(searchTimer);
    const query = currentQuery();
    try {
      const result = await fetchAdminUsers({ ...query, per_page: PER_PAGE });
      if (!result || !active) return;
      loadError = '';
      loaded = true;
      const pages = Math.max(1, Math.ceil(result.total / PER_PAGE));
      if (page > pages) {
        page = pages;
        return load();
      }
      remember(query);
    } catch (err) {
      if (active && !isMfaRequired(err)) loadError = errorMessage(err);
    }
  }

  function remember(query: AdminUserQuery) {
    const params = new URLSearchParams();
    if (query.q) params.set('q', query.q);
    if (query.role) params.set('role', query.role);
    if (query.status) params.set('status', query.status);
    if (query.plan_id) params.set('plan_id', query.plan_id);
    if (query.page && query.page > 1) params.set('page', String(query.page));
    const search = params.toString();
    adminState.usersQuery = search;
    syncedQuery = search;
    if (router.location === '/admin/users' && (router.querystring ?? '') !== search) {
      replace(search ? `/admin/users?${search}` : '/admin/users');
    }
  }

  function onSearchInput() {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(applyFilters, SEARCH_DELAY_MS);
  }

  function applyFilters() {
    page = 1;
    load();
  }

  function submitSearch(e: SubmitEvent) {
    e.preventDefault();
    applyFilters();
  }

  function clearFilters() {
    q = '';
    role = '';
    status = '';
    planId = '';
    applyFilters();
  }

  function goTo(next: number) {
    page = next;
    load();
  }
</script>

<AdminGate onunlock={load}>
  <form class="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-3 xl:grid-cols-[minmax(0,1fr)_170px_170px_190px]" role="search" onsubmit={submitSearch}>
    <Field
      type="search"
      icon="search"
      bind:value={q}
      oninput={onSearchInput}
      placeholder="User ID, exact email, or part of a username"
      aria-label="Search by user ID, exact email address, or part of a username"
      class="sm:col-span-3 xl:col-span-1"
    />
    <Select bind:value={role} onchange={applyFilters} aria-label="Role">
      <option value="">Any role</option>
      <option value="staff">All staff</option>
      {#each ROLES as r (r.value)}
        <option value={r.value}>{r.value === 'user' ? 'Members' : r.label}</option>
      {/each}
    </Select>
    <Select bind:value={status} onchange={applyFilters} aria-label="Status">
      <option value="">Any status</option>
      {#each USER_STATUSES as s (s.value)}
        <option value={s.value}>{s.label}</option>
      {/each}
    </Select>
    <Select bind:value={planId} onchange={applyFilters} aria-label="Plan">
      <option value="">Any plan</option>
      {#each adminState.plans as plan (plan.id)}
        <option value={plan.id}>{plan.name}</option>
      {/each}
    </Select>
  </form>

  {#if loadError}
    <Alert tone="danger" title="Could not load users" class="mb-4">
      {loadError}
      <Button variant="link" class="ml-1" onclick={load}>Try again</Button>
    </Alert>
  {/if}

  <Card padded={false}>
    {#if !loaded}
      <div class="flex flex-col gap-4 p-5" aria-busy="true">
        {#each Array(6) as _, i (i)}
          <div class="flex items-center gap-3">
            <Skeleton class="h-8 w-8" rounded="rounded-full" />
            <div class="flex-1"><Skeleton class="mb-1.5 h-3 w-1/4" /><Skeleton class="h-2.5 w-1/6" /></div>
            <Skeleton class="h-3 w-1/5" />
            <Skeleton class="h-3 w-16" />
          </div>
        {/each}
      </div>
    {:else if adminState.users.length === 0}
      <div class="p-5">
        {#if filtered}
          <EmptyState icon="search" title="No users match" description="Emails only match in full; usernames match any part. Try another search or clear the filters." compact>
            <Button variant="outline" size="sm" icon="x" onclick={clearFilters}>Clear filters</Button>
          </EmptyState>
        {:else}
          <EmptyState icon="users" title="No users yet" description="Accounts appear here as people register." compact />
        {/if}
      </div>
    {:else}
      <div class="overflow-x-auto">
        <table class="tbl min-w-[1100px] {adminState.loading ? 'opacity-60' : ''}" aria-busy={adminState.loading}>
          <thead>
            <tr>
              <th>User</th>
              <th>Email</th>
              <th>Role</th>
              <th>Plan</th>
              <th>2FA</th>
              <th>Status</th>
              <th class="text-right">Devices</th>
              <th>Last seen</th>
              <th>Joined</th>
            </tr>
          </thead>
          <tbody>
            {#each adminState.users as user (user.id)}
              <tr class="cursor-pointer" use:rowLink={`#/admin/users/${user.id}`}>
                <td>
                  <div class="flex items-center gap-3">
                    <Avatar name={user.full_name || user.username} size={32} />
                    <div class="min-w-0">
                      <a href="#/admin/users/{user.id}" class="block max-w-[220px] truncate font-medium text-fg hover:underline">{user.full_name || user.username}</a>
                      <p class="max-w-[220px] truncate text-[12px] text-dim">@{user.username}{user.id === userState.id ? ' · you' : ''}</p>
                    </div>
                  </div>
                </td>
                <td>
                  {#if user.email}
                    <span class="flex items-center gap-2">
                      <span class="max-w-[240px] truncate text-muted" title={user.email}>{user.email}</span>
                      {#if user.email_verified}
                        <span class="text-success" title="Email verified"><Icon name="check-circle" size={14} /><span class="sr-only">Verified</span></span>
                      {:else}
                        <Badge tone="gold">Unverified</Badge>
                      {/if}
                    </span>
                  {:else}
                    <span class="text-dim">—</span>
                  {/if}
                </td>
                <td>
                  {#if user.role === 'user'}<span class="text-muted">Member</span>{:else}<RoleBadge role={user.role} />{/if}
                </td>
                <td class={user.subscription_plan_name ? 'text-fg' : 'text-dim'}>{user.subscription_plan_name ?? 'No plan'}</td>
                <td>
                  {#if user.mfa_enabled}<Badge tone="mint" icon="shield-check">On</Badge>{:else}<Badge tone="neutral">Off</Badge>{/if}
                </td>
                <td>
                  {#if user.suspended_at}
                    <Badge tone="rose" icon="lock" title="Suspended {absoluteTime(user.suspended_at)}">Suspended</Badge>
                  {:else}
                    <span class="text-muted">Active</span>
                  {/if}
                </td>
                <td class="text-right font-mono text-muted">{user.device_count}</td>
                <td class="whitespace-nowrap text-muted">
                  {#if user.last_seen}
                    <time datetime={user.last_seen} title={absoluteTime(user.last_seen)}>{relativeTime(user.last_seen, clock.now)}</time>
                  {:else}
                    <span class="text-dim">Never</span>
                  {/if}
                </td>
                <td class="whitespace-nowrap text-muted"><time datetime={user.created_at} title={absoluteTime(user.created_at)}>{relativeTime(user.created_at, clock.now)}</time></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <Pager {page} perPage={PER_PAGE} total={adminState.usersTotal} noun="users" loading={adminState.loading} onpage={goTo} />
    {/if}
  </Card>
</AdminGate>
