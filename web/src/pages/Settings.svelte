<script lang="ts">
  import { onMount } from 'svelte';
  import { userState } from '../lib/stores/user.svelte';
  import { api } from '../lib/api';
  import Icon from '../components/Icon.svelte';

  let currentPassword = $state('');
  let newPassword = $state('');
  let message = $state('');
  let error = $state('');
  let loading = $state(false);

  interface SubscriptionInfo {
    plan_id: string | null;
    plan_name: string | null;
    plan_description: string | null;
    price: number | null;
    currency: string | null;
    billing_period: string | null;
    max_devices: number | null;
    max_clipboard_history: number | null;
    allowed_file_types: string[];
  }

  let subscription: SubscriptionInfo | null = $state(null);

  onMount(async () => {
    try {
      subscription = await api<SubscriptionInfo>('/api/me/subscription');
    } catch { /* ignore */ }
  });

  async function handleChangePassword(e: Event) {
    e.preventDefault();
    error = '';
    message = '';
    loading = true;

    try {
      await api('/api/me/password', {
        method: 'PUT',
        body: JSON.stringify({
          current_password: currentPassword,
          new_password: newPassword,
        }),
      });
      message = 'Password changed successfully.';
      currentPassword = '';
      newPassword = '';
    } catch (err: any) {
      error = err.message;
    } finally {
      loading = false;
    }
  }

  function formatBillingPeriod(period: string): string {
    if (period === 'monthly') return 'Monthly';
    if (period === 'yearly') return 'Yearly';
    if (period === 'lifetime') return 'Lifetime';
    return period;
  }
</script>

<div>
  <div class="bg-bg-card border border-border rounded-xl p-6 mb-5 transition-colors duration-200 hover:border-border-hover">
    <div class="flex items-center gap-3 mb-5 pb-4 border-b border-border">
      <div class="w-9 h-9 rounded flex items-center justify-center shrink-0 bg-[var(--accent-glow)] border border-[color-mix(in_srgb,var(--accent)_20%,transparent)] text-[var(--accent)]" style="--accent: var(--color-primary); --accent-glow: var(--color-primary-glow);">
        <Icon name="users" size={18} />
      </div>
      <h3 class="text-base font-semibold tracking-[-0.01em]">Account</h3>
    </div>
    <div class="flex items-center justify-between py-[11px] border-b border-border text-sm last-of-type:border-b-0">
      <span class="text-muted font-medium text-[13px]">Username</span>
      <span class="font-medium">{userState.username}</span>
    </div>
    <div class="flex items-center justify-between py-[11px] border-b border-border text-sm last-of-type:border-b-0">
      <span class="text-muted font-medium text-[13px]">User ID</span>
      <span class="font-mono text-[11px] text-dim px-2 py-[3px] bg-bg-input rounded-sm border border-border">{userState.id}</span>
    </div>
    <div class="flex items-center justify-between py-[11px] border-b border-border text-sm last-of-type:border-b-0">
      <span class="text-muted font-medium text-[13px]">Role</span>
      <span class="font-medium">
        {#if userState.isAdmin}
          <span class="text-xs px-2.5 py-[3px] rounded-full bg-primary-glow text-primary font-semibold border border-primary/20">Admin</span>
        {:else}
          <span class="text-xs px-2.5 py-[3px] rounded-full bg-bg-input text-muted font-semibold border border-border">User</span>
        {/if}
      </span>
    </div>
  </div>

  {#if subscription}
    <div class="bg-bg-card border border-border rounded-xl p-6 mb-5 transition-colors duration-200 hover:border-border-hover">
      <div class="flex items-center gap-3 mb-5 pb-4 border-b border-border">
        <div class="w-9 h-9 rounded flex items-center justify-center shrink-0 bg-[var(--accent-glow)] border border-[color-mix(in_srgb,var(--accent)_20%,transparent)] text-[var(--accent)]" style="--accent: var(--color-warning); --accent-glow: var(--color-warning-glow);">
          <Icon name="star" size={18} />
        </div>
        <h3 class="text-base font-semibold tracking-[-0.01em]">Subscription</h3>
      </div>
      {#if subscription.plan_name}
        <div class="flex items-center justify-between py-[11px] border-b border-border text-sm last-of-type:border-b-0">
          <span class="text-muted font-medium text-[13px]">Plan</span>
          <span class="px-3 py-[3px] rounded-full bg-primary-glow text-primary text-xs font-semibold border border-primary/20">{subscription.plan_name}</span>
        </div>
        {#if subscription.plan_description}
          <div class="flex items-center justify-between py-[11px] border-b border-border text-sm last-of-type:border-b-0">
            <span class="text-muted font-medium text-[13px]">Description</span>
            <span class="font-medium">{subscription.plan_description}</span>
          </div>
        {/if}
        <div class="flex items-center justify-between py-[11px] border-b border-border text-sm last-of-type:border-b-0">
          <span class="text-muted font-medium text-[13px]">Price</span>
          <span class="font-medium">
            {subscription.price === 0 ? 'Free' : `${subscription.currency} ${subscription.price?.toFixed(2)}`}
            {#if subscription.price && subscription.price > 0}
              <span class="text-muted text-[13px]">/ {subscription.billing_period ? formatBillingPeriod(subscription.billing_period) : ''}</span>
            {/if}
          </span>
        </div>
        <div class="flex items-center justify-between py-[11px] border-b border-border text-sm last-of-type:border-b-0">
          <span class="text-muted font-medium text-[13px]">Max Devices</span>
          <span class="font-medium">{subscription.max_devices ?? '—'}</span>
        </div>
        <div class="flex items-center justify-between py-[11px] border-b border-border text-sm last-of-type:border-b-0">
          <span class="text-muted font-medium text-[13px]">Clipboard History Limit</span>
          <span class="font-medium">{subscription.max_clipboard_history ?? '—'}</span>
        </div>
        <div class="flex items-center justify-between py-[11px] border-b border-border text-sm last-of-type:border-b-0">
          <span class="text-muted font-medium text-[13px]">Allowed File Types</span>
          <span class="font-medium">{subscription.allowed_file_types.length > 0 ? subscription.allowed_file_types.join(', ') : 'All'}</span>
        </div>
      {:else}
        <p class="py-3 text-sm text-muted">No subscription plan assigned. Contact the administrator for access.</p>
      {/if}
    </div>
  {/if}

  <div class="bg-bg-card border border-border rounded-xl p-6 mb-5 transition-colors duration-200 hover:border-border-hover">
    <div class="flex items-center gap-3 mb-5 pb-4 border-b border-border">
      <div class="w-9 h-9 rounded flex items-center justify-center shrink-0 bg-[var(--accent-glow)] border border-[color-mix(in_srgb,var(--accent)_20%,transparent)] text-[var(--accent)]" style="--accent: var(--color-success); --accent-glow: var(--color-success-glow);">
        <Icon name="key" size={18} />
      </div>
      <h3 class="text-base font-semibold tracking-[-0.01em]">Change Password</h3>
    </div>

    {#if message}
      <div class="flex items-center gap-2 bg-success-glow border border-success/30 text-success px-3.5 py-2.5 rounded text-[13px] mb-4"><Icon name="check" size={14} /> {message}</div>
    {/if}
    {#if error}
      <div class="flex items-center gap-2 bg-danger-glow border border-danger/30 text-danger px-3.5 py-2.5 rounded text-[13px] mb-4"><Icon name="x" size={14} /> {error}</div>
    {/if}

    <form onsubmit={handleChangePassword}>
      <label class="flex flex-col gap-1.5 mb-4">
        <span class="text-[13px] text-muted font-medium">Current Password</span>
        <input type="password" bind:value={currentPassword} required autocomplete="current-password"
          class="py-[11px] px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none max-w-[360px] transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
      </label>
      <label class="flex flex-col gap-1.5 mb-4">
        <span class="text-[13px] text-muted font-medium">New Password</span>
        <input type="password" bind:value={newPassword} required minlength="8" autocomplete="new-password"
          class="py-[11px] px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none max-w-[360px] transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
      </label>
      <button type="submit" class="inline-flex items-center gap-2 py-2.5 px-5 border-none rounded bg-primary text-white text-sm font-semibold transition-all duration-200 hover:not-disabled:bg-primary-hover hover:not-disabled:shadow-primary disabled:opacity-60" disabled={loading}>
        {#if loading}
          <span class="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-[spin_0.6s_linear_infinite]"></span>
        {:else}
          Change Password
        {/if}
      </button>
    </form>
  </div>
</div>
