<script lang="ts">
  import { userState } from '../../lib/stores/user.svelte';
  import {
    adminState,
    fetchAdminUsers,
    fetchAdminPlans,
    adminDeleteUser,
    adminAssignSubscription,
    adminRemoveSubscription,
  } from '../../lib/stores/admin.svelte';
  import { api } from '../../lib/api';
  import { push } from 'svelte-spa-router';

  let deleteConfirm = $state<string | null>(null);
  let assigningUser = $state<string | null>(null);
  let selectedPlan = $state('');
  let error = $state('');

  $effect(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    fetchAdminUsers();
    fetchAdminPlans();
  });

  async function handleDelete(id: string) {
    await adminDeleteUser(id);
    deleteConfirm = null;
  }

  async function handleAssign(userId: string) {
    error = '';
    try {
      if (selectedPlan) {
        await adminAssignSubscription(userId, selectedPlan);
      } else {
        await adminRemoveSubscription(userId);
      }
      assigningUser = null;
      selectedPlan = '';
      await fetchAdminUsers();
    } catch (err: any) {
      error = err.message;
    }
  }

  async function handleVerifyEmail(userId: string) {
    try {
      await api(`/api/admin/users/${userId}/verify-email`, { method: 'PUT' });
      await fetchAdminUsers();
    } catch (err: any) {
      error = err.message;
    }
  }

  function startAssign(userId: string, currentPlanId: string | null) {
    assigningUser = userId;
    selectedPlan = currentPlanId ?? '';
    error = '';
  }
</script>

<div>
  <h2 class="text-xl font-semibold mb-6">All Users</h2>

  {#if error}
    <div class="flex items-center gap-2 bg-danger-glow border border-danger/30 text-danger px-3.5 py-2.5 rounded text-[13px] mb-4">{error}</div>
  {/if}

  {#if adminState.loading}
    <p class="text-muted text-[13px]">Loading...</p>
  {:else}
    <div class="bg-bg-card border border-border rounded-xl overflow-hidden">
      <div class="overflow-x-auto">
      <table class="w-full border-collapse">
        <thead>
          <tr>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Username</th>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Full Name</th>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Email</th>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Verified</th>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Provider</th>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Role</th>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Plan</th>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Devices</th>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold">Created</th>
            <th class="text-left px-[18px] py-[13px] text-[11px] uppercase tracking-[0.06em] text-dim border-b border-border font-semibold"></th>
          </tr>
        </thead>
        <tbody>
          {#each adminState.users as user}
            <tr class="transition-colors duration-150 hover:bg-bg-hover">
              <td class="px-[18px] py-[13px] text-sm border-b border-border font-semibold">{user.username}</td>
              <td class="px-[18px] py-[13px] text-sm border-b border-border">{user.full_name || '—'}</td>
              <td class="px-[18px] py-[13px] text-sm border-b border-border">{user.email || '—'}</td>
              <td class="px-[18px] py-[13px] text-sm border-b border-border">
                {#if user.email_verified}
                  <span class="inline-block px-2.5 py-[3px] rounded-full bg-success/10 text-success text-[11px] font-semibold uppercase border border-success/20">Verified</span>
                {:else}
                  <button
                    class="inline-block px-2.5 py-[3px] rounded-full bg-warning/10 text-warning text-[11px] font-semibold uppercase border border-warning/20 cursor-pointer hover:bg-warning/20 transition-colors"
                    onclick={() => handleVerifyEmail(user.id)}
                    title="Click to manually verify"
                  >Unverified</button>
                {/if}
              </td>
              <td class="px-[18px] py-[13px] text-sm border-b border-border">
                <span class="inline-block px-2.5 py-[3px] rounded-full bg-bg-input text-muted text-[11px] font-semibold capitalize border border-border">{user.auth_provider || 'local'}</span>
              </td>
              <td class="px-[18px] py-[13px] text-sm border-b border-border">
                {#if user.is_admin}
                  <span class="inline-block px-2.5 py-[3px] rounded-full bg-primary-glow text-primary text-[11px] font-semibold uppercase border border-primary/20">Admin</span>
                {:else}
                  <span class="inline-block px-2.5 py-[3px] rounded-full bg-bg-input text-muted text-[11px] font-semibold uppercase border border-border">User</span>
                {/if}
              </td>
              <td class="px-[18px] py-[13px] text-sm border-b border-border">
                {#if assigningUser === user.id}
                  <div class="flex items-center gap-1.5">
                    <select bind:value={selectedPlan} class="py-1.5 px-2.5 border border-border rounded bg-bg-input text-text text-[13px] outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]">
                      <option value="">No Plan</option>
                      {#each adminState.plans as plan}
                        <option value={plan.id}>{plan.name}</option>
                      {/each}
                    </select>
                    <button class="border-none rounded text-xs font-medium py-1.5 px-3 transition-all duration-150 bg-primary text-white hover:bg-primary-hover" onclick={() => handleAssign(user.id)}>Save</button>
                    <button class="border border-border rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => (assigningUser = null)}>Cancel</button>
                  </div>
                {:else}
                  <span
                    class="cursor-pointer px-2.5 py-[3px] rounded-full text-[13px] transition-all duration-150 bg-bg-input border border-border hover:bg-bg-hover hover:border-border-hover"
                    onclick={() => startAssign(user.id, user.subscription_plan_id)}
                    role="button"
                    tabindex="0"
                    onkeydown={(e) => e.key === 'Enter' && startAssign(user.id, user.subscription_plan_id)}
                  >
                    {user.subscription_plan_name ?? '—'}
                  </span>
                {/if}
              </td>
              <td class="px-[18px] py-[13px] text-sm border-b border-border">{user.device_count}</td>
              <td class="px-[18px] py-[13px] text-[13px] border-b border-border text-muted">{new Date(user.created_at).toLocaleDateString()}</td>
              <td class="px-[18px] py-[13px] text-sm border-b border-border">
                {#if user.id !== userState.id}
                  {#if deleteConfirm === user.id}
                    <div class="flex items-center gap-2">
                      <span class="text-[13px] text-warning font-medium">Delete?</span>
                      <button class="border-none rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-danger text-white hover:bg-danger-hover" onclick={() => handleDelete(user.id)}>Yes</button>
                      <button class="border border-border rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => (deleteConfirm = null)}>No</button>
                    </div>
                  {:else}
                    <button class="border border-border rounded text-[13px] font-medium py-1.5 px-3 transition-all duration-150 bg-transparent text-muted hover:bg-bg-hover hover:text-text hover:border-border-hover" onclick={() => (deleteConfirm = user.id)}>Delete</button>
                  {/if}
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
      </div>
    </div>
  {/if}
</div>
