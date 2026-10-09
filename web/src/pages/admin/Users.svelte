<script lang="ts">
  import { onMount } from 'svelte';
  import { userState } from '../../lib/stores/user.svelte';
  import {
    adminState,
    fetchAdminUsers,
    fetchAdminPlans,
    adminDeleteUser,
    adminAssignSubscription,
    adminRemoveSubscription,
    type AdminUserRow,
  } from '../../lib/stores/admin.svelte';
  import { toast } from '../../lib/stores/toast.svelte';
  import { api } from '../../lib/api';
  import { push } from 'svelte-spa-router';
  import { createClock } from '../../lib/clock.svelte';
  import { absoluteTime, relativeTime, titleCase } from '../../lib/format';
  import Icon from '../../components/Icon.svelte';
  import Avatar from '../../components/ui/Avatar.svelte';
  import Badge from '../../components/ui/Badge.svelte';
  import Button from '../../components/ui/Button.svelte';
  import Card from '../../components/ui/Card.svelte';
  import ConfirmAction from '../../components/ui/ConfirmAction.svelte';
  import Dialog from '../../components/ui/Dialog.svelte';
  import Select from '../../components/ui/Select.svelte';
  import EmptyState from '../../components/ui/EmptyState.svelte';
  import Skeleton from '../../components/ui/Skeleton.svelte';

  const clock = createClock();
  let query = $state('');
  let planDialog = $state(false);
  let planUser = $state<AdminUserRow | null>(null);
  let selectedPlan = $state('');
  let saving = $state(false);

  onMount(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    fetchAdminUsers();
    fetchAdminPlans();
  });

  const filtered = $derived.by(() => {
    const q = query.trim().toLowerCase();
    if (!q) return adminState.users;
    return adminState.users.filter((u) => [u.username, u.full_name, u.email, u.subscription_plan_name ?? ''].some((v) => (v || '').toLowerCase().includes(q)));
  });

  const verifiedCount = $derived(adminState.users.filter((u) => u.email_verified).length);
  const adminCount = $derived(adminState.users.filter((u) => u.is_admin).length);

  function openPlanDialog(user: AdminUserRow) {
    planUser = user;
    selectedPlan = user.subscription_plan_id ?? '';
    planDialog = true;
  }

  async function savePlan() {
    if (!planUser) return;
    saving = true;
    try {
      if (selectedPlan) await adminAssignSubscription(planUser.id, selectedPlan);
      else await adminRemoveSubscription(planUser.id);
      await fetchAdminUsers();
      toast.success('Plan updated', `${planUser.username} is now on ${selectedPlan ? adminState.plans.find((p) => p.id === selectedPlan)?.name ?? 'the selected plan' : 'no plan'}.`);
      planDialog = false;
    } catch (err: any) {
      toast.error('Could not update plan', err.message);
    } finally {
      saving = false;
    }
  }

  async function handleDelete(user: AdminUserRow) {
    try {
      await adminDeleteUser(user.id);
      toast.success('User deleted', `${user.username} and their devices were removed.`);
    } catch (err: any) {
      toast.error('Could not delete user', err.message);
    }
  }

  async function handleVerifyEmail(user: AdminUserRow) {
    try {
      await api(`/api/admin/users/${user.id}/verify-email`, { method: 'PUT' });
      await fetchAdminUsers();
      toast.success('Email verified', `${user.username} can now sign in.`);
    } catch (err: any) {
      toast.error('Could not verify email', err.message);
    }
  }
</script>

<div class="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
  <div class="flex flex-wrap items-center gap-2">
    <Badge tone="neutral">{adminState.users.length} users</Badge>
    <Badge tone="mint" icon="check">{verifiedCount} verified</Badge>
    <Badge tone="cyan" icon="shield">{adminCount} admin{adminCount === 1 ? '' : 's'}</Badge>
  </div>
  <div class="relative">
    <span class="pointer-events-none absolute inset-y-0 left-3 flex items-center text-ink/60"><Icon name="search" size={14} strokeWidth={2.5} /></span>
    <input
      type="search"
      bind:value={query}
      placeholder="Search name, email, plan…"
      class="h-10 w-full rounded-md border-2 border-ink bg-surface pl-9 pr-3 text-[13px] text-ink shadow-xs outline-none transition-[box-shadow,transform] placeholder:text-dim focus:-translate-x-px focus:-translate-y-px focus:shadow-md sm:w-72"
    />
  </div>
</div>

<Card padded={false}>
  {#if adminState.loading && adminState.users.length === 0}
    <div class="flex flex-col gap-3 p-5">
      {#each Array(5) as _, i (i)}
        <div class="flex items-center gap-3"><Skeleton class="h-8 w-8" rounded="rounded-full" /><Skeleton class="h-3 w-1/4" /><Skeleton class="h-3 w-1/5" /><Skeleton class="ml-auto h-3 w-16" /></div>
      {/each}
    </div>
  {:else if filtered.length === 0}
    <div class="p-5">
      <EmptyState icon="users" title={query ? 'No users match' : 'No users yet'} description={query ? 'Try a different search term.' : 'Accounts will appear here as people register.'} compact />
    </div>
  {:else}
    <div class="overflow-x-auto">
      <table class="tbl min-w-[960px]">
        <thead>
          <tr>
            <th>User</th>
            <th>Email</th>
            <th>Provider</th>
            <th>Role</th>
            <th>Plan</th>
            <th class="text-right">Devices</th>
            <th>Joined</th>
            <th class="text-right"><span class="sr-only">Actions</span></th>
          </tr>
        </thead>
        <tbody>
          {#each filtered as user (user.id)}
            <tr>
              <td>
                <div class="flex items-center gap-3">
                  <Avatar name={user.full_name || user.username} size={32} />
                  <div class="min-w-0">
                    <p class="truncate font-medium text-fg">{user.full_name || user.username}</p>
                    <p class="truncate text-[12px] text-dim">@{user.username}{user.id === userState.id ? ' · you' : ''}</p>
                  </div>
                </div>
              </td>
              <td>
                <div class="flex items-center gap-2">
                  <span class="truncate text-muted">{user.email || '—'}</span>
                  {#if user.email}
                    {#if user.email_verified}
                      <Badge tone="mint" icon="check" title="Email verified">Verified</Badge>
                    {:else}
                      <button type="button" class="inline-flex" title="Click to verify manually" onclick={() => handleVerifyEmail(user)}>
                        <Badge tone="gold" icon="alert-circle" class="cursor-pointer transition-colors hover:bg-gold/20">Unverified</Badge>
                      </button>
                    {/if}
                  {/if}
                </div>
              </td>
              <td><Badge tone="neutral">{titleCase(user.auth_provider || 'local')}</Badge></td>
              <td>
                {#if user.is_admin}<Badge tone="cyan" uppercase>admin</Badge>{:else}<span class="text-muted">Member</span>{/if}
              </td>
              <td>
                <button
                  type="button"
                  class="group inline-flex items-center gap-1.5 rounded-md border-2 border-ink bg-surface py-1 pl-2.5 pr-2 text-[12.5px] font-semibold text-ink shadow-xs transition-[background-color,transform,box-shadow] hover:-translate-x-px hover:-translate-y-px hover:bg-yellow hover:shadow-sm"
                  onclick={() => openPlanDialog(user)}
                  title="Change plan"
                >
                  {user.subscription_plan_name ?? 'No plan'}
                  <Icon name="edit" size={11} class="text-ink/60 transition-colors group-hover:text-ink" strokeWidth={2.5} />
                </button>
              </td>
              <td class="text-right font-mono text-muted">{user.device_count}</td>
              <td class="text-muted"><time datetime={user.created_at} title={absoluteTime(user.created_at)}>{relativeTime(user.created_at, clock.now)}</time></td>
              <td class="text-right">
                {#if user.id !== userState.id}
                  <ConfirmAction size="icon-sm" variant="ghost" label="Delete user" confirmLabel="Delete" prompt="Delete user?" onconfirm={() => handleDelete(user)} />
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</Card>

<Dialog bind:open={planDialog} title="Change subscription plan" description={planUser ? `Applies to @${planUser.username}` : undefined} size="sm">
  <Select label="Plan" bind:value={selectedPlan} hint="Choosing “No plan” removes the current subscription.">
    <option value="">No plan</option>
    {#each adminState.plans as plan (plan.id)}
      <option value={plan.id}>{plan.name} — {plan.max_devices} devices · {plan.max_clipboard_history} entries</option>
    {/each}
  </Select>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (planDialog = false)}>Cancel</Button>
    <Button loading={saving} onclick={savePlan}>Save plan</Button>
  {/snippet}
</Dialog>
