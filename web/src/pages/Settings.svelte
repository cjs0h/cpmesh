<script lang="ts">
  import { onMount } from 'svelte';
  import { userState } from '../lib/stores/user.svelte';
  import { devicesState, fetchDevices } from '../lib/stores/devices.svelte';
  import { toast } from '../lib/stores/toast.svelte';
  import { api } from '../lib/api';
  import { titleCase, truncateMiddle } from '../lib/format';
  import Icon from '../components/Icon.svelte';
  import Avatar from '../components/ui/Avatar.svelte';
  import Badge from '../components/ui/Badge.svelte';
  import Button from '../components/ui/Button.svelte';
  import Card from '../components/ui/Card.svelte';
  import Field from '../components/ui/Field.svelte';
  import CopyButton from '../components/ui/CopyButton.svelte';
  import Alert from '../components/ui/Alert.svelte';
  import TwoFactorSettings from '../components/mfa/TwoFactorSettings.svelte';

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

  let currentPassword = $state('');
  let newPassword = $state('');
  let confirmPassword = $state('');
  let error = $state('');
  let loading = $state(false);
  let subscription = $state<SubscriptionInfo | null>(null);

  onMount(async () => {
    fetchDevices();
    try {
      subscription = await api<SubscriptionInfo>('/api/me/subscription');
    } catch {
      /* subscription is optional */
    }
  });

  const displayName = $derived(userState.fullName || userState.username);
  const isLocal = $derived(userState.authProvider === 'local');
  const roleLabel = $derived(userState.role === 'user' ? 'Member' : titleCase(userState.role));
  const deviceUsage = $derived.by(() => {
    const max = subscription?.max_devices ?? null;
    const used = devicesState.list.length;
    return { used, max, pct: max ? Math.min(100, Math.round((used / max) * 100)) : 0 };
  });

  const strength = $derived.by(() => {
    const p = newPassword;
    if (!p) return { score: 0, label: '', tone: 'bg-surface-3' };
    let score = 0;
    if (p.length >= 8) score++;
    if (p.length >= 12) score++;
    if (/[A-Z]/.test(p) && /[a-z]/.test(p)) score++;
    if (/\d/.test(p)) score++;
    if (/[^A-Za-z0-9]/.test(p)) score++;
    const labels = ['Weak', 'Weak', 'Fair', 'Good', 'Strong', 'Excellent'];
    const tones = ['bg-danger', 'bg-danger', 'bg-warning', 'bg-fg', 'bg-success', 'bg-success'];
    return { score, label: labels[score], tone: tones[score] };
  });

  const mismatch = $derived(confirmPassword.length > 0 && newPassword !== confirmPassword);

  async function handleChangePassword(e: Event) {
    e.preventDefault();
    error = '';
    if (newPassword !== confirmPassword) {
      error = 'The new passwords do not match.';
      return;
    }
    loading = true;
    try {
      await api('/api/me/password', {
        method: 'PUT',
        body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
      });
      toast.success('Password updated', 'Use your new password the next time you sign in.');
      currentPassword = '';
      newPassword = '';
      confirmPassword = '';
    } catch (err: any) {
      error = err.message;
    } finally {
      loading = false;
    }
  }

  function formatBilling(period: string | null): string {
    if (!period) return '';
    return period === 'lifetime' ? 'one-time' : `per ${period.replace('ly', '')}`;
  }
</script>

<div class="grid grid-cols-1 gap-6 xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
  <div class="flex flex-col gap-6">
    <!-- Profile -->
    <Card title="Profile" description="How you appear across your devices" icon="user" accent="accent">
      <div class="flex flex-col gap-5 sm:flex-row sm:items-center">
        <Avatar name={displayName} src={userState.avatarUrl} size={72} />
        <div class="min-w-0 flex-1">
          <div class="flex flex-wrap items-center gap-2">
            <h3 class="text-lg font-semibold tracking-tight text-fg">{displayName}</h3>
            {#if userState.isAdmin}<Badge tone="cyan" uppercase>{userState.role}</Badge>{/if}
            {#if userState.emailVerified}
              <Badge tone="mint" icon="check">Verified</Badge>
            {:else if userState.email}
              <Badge tone="gold" icon="alert-circle">Email unverified</Badge>
            {/if}
          </div>
          <p class="mt-1 text-sm text-muted">@{userState.username}{userState.email ? ` · ${userState.email}` : ''}</p>
          <p class="mt-2 inline-flex items-center gap-1.5 text-[12px] text-dim">
            <Icon name={isLocal ? 'key' : 'globe'} size={12} />
            Signs in with {isLocal ? 'a password' : titleCase(userState.authProvider)}
          </p>
        </div>
      </div>

      <dl class="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div class="rounded-md border border-border bg-bg-deep px-4 py-3">
          <dt class="text-xs text-muted">User ID</dt>
          <dd class="mt-1 flex items-center justify-between gap-2">
            <code class="truncate font-mono text-[12.5px] text-muted" title={userState.id}>{truncateMiddle(userState.id, 10)}</code>
            <CopyButton text={userState.id} label="Copy user ID" />
          </dd>
        </div>
        <div class="rounded-md border border-border bg-bg-deep px-4 py-3">
          <dt class="text-xs text-muted">Role</dt>
          <dd class="mt-1 text-sm font-medium text-fg">{roleLabel}</dd>
        </div>
      </dl>
    </Card>

    <!-- Security -->
    <Card title="Password" description={isLocal ? 'Choose something long and unique' : 'Managed by your identity provider'} icon="lock" accent="mint">
      {#if !isLocal}
        <Alert tone="info">
          Your account signs in through <strong class="text-fg">{titleCase(userState.authProvider)}</strong>. Change your password there — it is not stored on this relay.
        </Alert>
      {:else}
        <form onsubmit={handleChangePassword} class="flex max-w-md flex-col gap-4">
          {#if error}
            <Alert tone="danger" dismissible ondismiss={() => (error = '')}>{error}</Alert>
          {/if}
          <Field label="Current password" type="password" icon="lock" bind:value={currentPassword} required autocomplete="current-password" />
          <div class="flex flex-col gap-2">
            <Field label="New password" type="password" icon="key" bind:value={newPassword} required minlength={8} maxlength={128} autocomplete="new-password" />
            {#if newPassword}
              <div class="flex items-center gap-3 px-0.5">
                <div class="flex flex-1 gap-1" aria-hidden="true">
                  {#each Array(5) as _, i (i)}
                    <span class="h-1 flex-1 rounded-full transition-colors duration-200 {i < strength.score ? strength.tone : 'bg-surface-3'}"></span>
                  {/each}
                </div>
                <span class="w-16 text-right text-[11.5px] font-medium text-muted">{strength.label}</span>
              </div>
            {/if}
          </div>
          <Field label="Confirm new password" type="password" icon="check" bind:value={confirmPassword} required autocomplete="new-password" error={mismatch ? 'Passwords do not match' : undefined} />
          <div>
            <Button type="submit" {loading} disabled={mismatch || !currentPassword || !newPassword}>Update password</Button>
          </div>
        </form>
      {/if}
    </Card>

    <TwoFactorSettings />
  </div>

  <div class="flex flex-col gap-6">
    <!-- Plan -->
    <Card title="Plan" description={subscription?.plan_name ? 'Your current subscription' : 'No plan assigned'} icon="star" accent="gold">
      {#if subscription?.plan_name}
        <div class="flex items-start justify-between gap-3">
          <div>
            <p class="text-lg font-semibold tracking-tight text-fg">{subscription.plan_name}</p>
            {#if subscription.plan_description}<p class="mt-0.5 text-[13px] text-muted">{subscription.plan_description}</p>{/if}
          </div>
          <div class="text-right">
            <p class="text-lg font-semibold tracking-tight text-fg">
              {subscription.price === 0 || subscription.price == null ? 'Free' : `${subscription.currency ?? ''} ${subscription.price.toFixed(2)}`}
            </p>
            {#if subscription.price && subscription.price > 0}<p class="text-[11.5px] text-dim">{formatBilling(subscription.billing_period)}</p>{/if}
          </div>
        </div>

        <div class="mt-5 flex flex-col gap-4">
          <div>
            <div class="mb-1.5 flex items-center justify-between text-[12.5px]">
              <span class="text-muted">Devices</span>
              <span class="font-mono text-fg">{deviceUsage.used}<span class="text-dim"> / {deviceUsage.max ?? '∞'}</span></span>
            </div>
            <div class="h-1.5 overflow-hidden rounded-full bg-surface-3">
              <div class="h-full rounded-full bg-ink transition-[width] duration-500 ease-[var(--ease-out-expo)]" style="width: {deviceUsage.max ? deviceUsage.pct : 12}%;"></div>
            </div>
          </div>
          <dl class="grid grid-cols-2 gap-3 text-[13px]">
            <div class="rounded-md border border-border bg-bg-deep px-3 py-2.5">
              <dt class="text-xs text-muted">History limit</dt>
              <dd class="mt-0.5 font-medium text-fg">{subscription.max_clipboard_history ?? 'Unlimited'}</dd>
            </div>
            <div class="rounded-md border border-border bg-bg-deep px-3 py-2.5">
              <dt class="text-xs text-muted">File types</dt>
              <dd class="mt-0.5 truncate font-medium text-fg" title={subscription.allowed_file_types.join(', ')}>
                {subscription.allowed_file_types.length > 0 ? subscription.allowed_file_types.join(', ') : 'All'}
              </dd>
            </div>
          </dl>
        </div>
      {:else}
        <p class="text-sm leading-relaxed text-muted">No subscription plan is assigned to your account yet. Ask the relay administrator to assign one if you hit device or history limits.</p>
      {/if}
    </Card>

    <!-- Encryption facts -->
    <div class="rounded-lg border border-border bg-surface p-5">
      <div class="flex items-start gap-3">
        <span class="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-border bg-surface-2 text-fg"><Icon name="shield-check" size={17} /></span>
        <div>
          <p class="text-sm font-medium text-fg">Your keys never leave your devices</p>
          <p class="mt-1 text-[13px] leading-relaxed text-muted">
            Passwords only protect this dashboard. Clipboard content is sealed on-device with AES-256-GCM and pairing keys exchanged over ECDH — resetting a password never exposes a clip.
          </p>
        </div>
      </div>
    </div>
  </div>
</div>
