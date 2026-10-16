<script lang="ts">
  import { onMount } from 'svelte';
  import { push } from 'svelte-spa-router';
  import { ApiError } from '../../lib/api';
  import { can, userState, type Permission, type Role } from '../../lib/stores/user.svelte';
  import {
    adminAssignSubscription,
    adminDeleteUser,
    adminRemoveSubscription,
    adminResendVerification,
    adminResetMfa,
    adminRevokeSessions,
    adminSetRole,
    adminState,
    adminSuspendUser,
    adminUnsuspendUser,
    adminVerifyEmail,
    auditActionLabel,
    auditActionTone,
    errorMessage,
    fetchAdminPlans,
    fetchAdminUser,
    isMfaRequired,
    roleLabel,
    ROLES,
    type AdminDevice,
    type AdminUserDetail,
  } from '../../lib/stores/admin.svelte';
  import { toast } from '../../lib/stores/toast.svelte';
  import { createClock } from '../../lib/clock.svelte';
  import { absoluteTime, relativeTime, titleCase, truncateMiddle } from '../../lib/format';
  import Icon from '../../components/Icon.svelte';
  import Alert from '../../components/ui/Alert.svelte';
  import Avatar from '../../components/ui/Avatar.svelte';
  import Badge from '../../components/ui/Badge.svelte';
  import Button from '../../components/ui/Button.svelte';
  import Card from '../../components/ui/Card.svelte';
  import ConfirmAction from '../../components/ui/ConfirmAction.svelte';
  import CopyButton from '../../components/ui/CopyButton.svelte';
  import Dialog from '../../components/ui/Dialog.svelte';
  import EmptyState from '../../components/ui/EmptyState.svelte';
  import Select from '../../components/ui/Select.svelte';
  import Skeleton from '../../components/ui/Skeleton.svelte';
  import AdminGate from '../../components/admin/AdminGate.svelte';
  import RoleBadge from '../../components/admin/RoleBadge.svelte';
  import TextArea from '../../components/admin/TextArea.svelte';

  let { params }: { params?: { id?: string } } = $props();

  const clock = createClock();
  let detail = $state<AdminUserDetail | null>(null);
  let loading = $state(true);
  let notFound = $state(false);
  let loadError = $state('');
  /** The action in progress, e.g. "plan" or "suspend". */
  let busy = $state<string | null>(null);

  let planChoice = $state('');
  let roleChoice = $state('user');
  let suspendOpen = $state(false);
  let suspendReason = $state('');

  const backHref = $derived(`#/admin/users${adminState.usersQuery ? `?${adminState.usersQuery}` : ''}`);

  onMount(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    load();
    if (can('manage_users')) fetchAdminPlans().catch(() => {});
  });

  async function load() {
    const id = params?.id;
    if (!id) {
      notFound = true;
      loading = false;
      return;
    }
    loading = true;
    try {
      const next = await fetchAdminUser(id);
      detail = next;
      planChoice = next.user.subscription_plan_id ?? '';
      roleChoice = next.user.role;
      notFound = false;
      loadError = '';
    } catch (err) {
      if (err instanceof ApiError && (err.status === 404 || err.status === 400)) notFound = true;
      else if (!isMfaRequired(err)) loadError = errorMessage(err);
    } finally {
      loading = false;
    }
  }

  const isSelf = $derived(detail?.user.id === userState.id);
  const targetIsStaff = $derived(Boolean(detail && detail.user.role !== 'user'));

  /** Acting on a staff account also needs the staff permission. */
  function allowed(permission: Permission): boolean {
    return can(permission) && (!targetIsStaff || can('manage_staff'));
  }

  const canManage = $derived(allowed('manage_users'));
  const canSuspend = $derived(canManage && !isSelf);
  const canRevoke = $derived(canManage && !isSelf);
  const canResetMfa = $derived(allowed('reset_mfa') && !isSelf);
  const canDelete = $derived(allowed('delete_users') && !isSelf);
  const canSetRole = $derived(can('manage_staff') && !isSelf);

  const restriction = $derived.by(() => {
    if (!detail) return '';
    if (isSelf) return 'This is your account. Suspending, signing out, resetting 2FA, changing the role and deleting are not available on it; manage your own security in Settings.';
    if (targetIsStaff && !can('manage_staff')) return 'This is a staff account: only owners can change it.';
    if (!can('manage_users')) return 'Your role can view this account but not change it.';
    return '';
  });

  const handle = $derived(detail ? `@${detail.user.username}` : '');

  async function run(key: string, action: () => Promise<unknown>, success: string, description: string, failure: string): Promise<boolean> {
    busy = key;
    try {
      await action();
      toast.success(success, description);
      await load();
      return true;
    } catch (err) {
      if (!isMfaRequired(err)) toast.error(failure, errorMessage(err));
      return false;
    } finally {
      busy = null;
    }
  }

  function savePlan(e: SubmitEvent) {
    e.preventDefault();
    if (!detail) return;
    const id = detail.user.id;
    const plan = adminState.plans.find((p) => p.id === planChoice);
    run(
      'plan',
      () => (planChoice ? adminAssignSubscription(id, planChoice) : adminRemoveSubscription(id)),
      'Plan updated',
      plan ? `${handle} is now on ${plan.name}.` : `${handle} no longer has a plan.`,
      'Could not change the plan',
    );
  }

  function verifyEmail() {
    if (!detail) return;
    const id = detail.user.id;
    run('verify', () => adminVerifyEmail(id), 'Email verified', `${handle} can now sign in with their email address.`, 'Could not verify the email');
  }

  function resendVerification() {
    if (!detail) return;
    const { id, email } = detail.user;
    run('resend', () => adminResendVerification(id), 'Verification email sent', `Sent to ${email}.`, 'Could not send the email');
  }

  async function revokeSessions() {
    if (!detail) return;
    const id = detail.user.id;
    await run('revoke', () => adminRevokeSessions(id), 'Signed out everywhere', `${handle} has to sign in again on every device.`, 'Could not sign them out');
  }

  async function resetMfa() {
    if (!detail) return;
    const id = detail.user.id;
    await run('mfa', () => adminResetMfa(id), 'Two-factor authentication reset', `${handle} was signed out and sets up a second factor at their next sign-in.`, 'Could not reset 2FA');
  }

  function openSuspend() {
    suspendReason = '';
    suspendOpen = true;
  }

  async function suspend(e: SubmitEvent) {
    e.preventDefault();
    if (!detail) return;
    const id = detail.user.id;
    const reason = suspendReason.trim();
    if (await run('suspend', () => adminSuspendUser(id, reason), 'Account suspended', `${handle} was signed out everywhere and can’t sign in.`, 'Could not suspend the account')) {
      suspendOpen = false;
    }
  }

  function unsuspend() {
    if (!detail) return;
    const id = detail.user.id;
    run('unsuspend', () => adminUnsuspendUser(id), 'Account reinstated', `${handle} can sign in again.`, 'Could not reinstate the account');
  }

  function saveRole(e: SubmitEvent) {
    e.preventDefault();
    if (!detail) return;
    const id = detail.user.id;
    const next = roleChoice as Role;
    run('role', () => adminSetRole(id, next), 'Role updated', `${handle} is now: ${roleLabel(next)}.`, 'Could not change the role');
  }

  async function remove() {
    if (!detail) return;
    const { id } = detail.user;
    const who = handle;
    busy = 'delete';
    try {
      await adminDeleteUser(id);
      toast.success('User deleted', `${who}, their devices and clipboard history were removed.`);
      push(backHref.slice(1));
    } catch (err) {
      if (!isMfaRequired(err)) toast.error('Could not delete the user', errorMessage(err));
    } finally {
      busy = null;
    }
  }

  function deviceStatus(device: AdminDevice): { tone: 'mint' | 'gold' | 'rose' | 'neutral'; label: string } {
    if (device.status === 'pending') return { tone: 'gold', label: 'Pending approval' };
    if (device.status === 'rejected') return { tone: 'rose', label: 'Rejected' };
    if (device.status === 'revoked') return { tone: 'rose', label: 'Revoked' };
    return device.online ? { tone: 'mint', label: 'Online' } : { tone: 'neutral', label: 'Offline' };
  }

  const onlineDevices = $derived(detail?.devices.filter((d) => d.online).length ?? 0);
</script>

{#snippet when(value: string | null, empty: string)}
  {#if value}
    <time datetime={value} title={absoluteTime(value)}>{relativeTime(value, clock.now)}</time>
  {:else}
    <span class="text-dim">{empty}</span>
  {/if}
{/snippet}

{#snippet userLink(id: string | null, name: string | null)}
  {#if id && name}
    <a href="#/admin/users/{id}" class="font-medium text-fg hover:underline">@{name}</a>
  {:else if id}
    <span class="text-dim" title={id}>a deleted user</span>
  {/if}
{/snippet}

<AdminGate onunlock={load}>
  <a href={backHref} class="mb-5 inline-flex items-center gap-1.5 text-[13px] text-muted transition-colors duration-150 hover:text-fg">
    <Icon name="arrow-left" size={14} /> All users
  </a>

  {#if notFound}
    <EmptyState icon="user" title="User not found" description="This account does not exist, or it was deleted.">
      <Button variant="outline" size="sm" icon="users" href={backHref}>Back to users</Button>
    </EmptyState>
  {:else if !detail && loadError}
    <Alert tone="danger" title="Could not load this user">
      {loadError}
      <Button variant="link" class="ml-1" onclick={load}>Try again</Button>
    </Alert>
  {:else if !detail}
    <div class="flex items-center gap-4" aria-busy="true">
      <Skeleton class="h-14 w-14" rounded="rounded-full" />
      <div class="flex-1"><Skeleton class="mb-2 h-5 w-1/4" /><Skeleton class="h-3 w-1/3" /></div>
    </div>
    <div class="mt-8 grid grid-cols-1 gap-6 lg:grid-cols-2">
      {#each Array(4) as _, i (i)}
        <div class="rounded-lg border border-border bg-surface p-5"><Skeleton class="mb-4 h-3.5 w-1/3" /><Skeleton class="mb-2 h-3 w-full" /><Skeleton class="h-3 w-2/3" /></div>
      {/each}
    </div>
  {:else}
    {@const user = detail.user}
    <header class="mb-6 flex flex-col gap-4 sm:flex-row sm:items-start">
      <Avatar name={user.full_name || user.username} size={56} />
      <div class="min-w-0 flex-1">
        <div class="flex flex-wrap items-center gap-2">
          <h1 class="truncate text-xl font-semibold tracking-tight text-fg">{user.full_name || user.username}</h1>
          <RoleBadge role={user.role} />
          {#if detail.mfa.enabled}
            <Badge tone="mint" icon="shield-check">2FA on</Badge>
          {:else}
            <Badge tone={detail.mfa.required ? 'gold' : 'neutral'} icon="shield">2FA off</Badge>
          {/if}
          {#if user.suspended_at}<Badge tone="rose" icon="lock">Suspended</Badge>{/if}
          {#if isSelf}<Badge tone="neutral">You</Badge>{/if}
        </div>
        <p class="mt-1 truncate text-sm text-muted">@{user.username}{user.email ? ` · ${user.email}` : ''}</p>
        <dl class="mt-3 flex flex-wrap gap-x-6 gap-y-1.5 text-[12.5px]">
          <div class="flex items-center gap-1.5"><dt class="text-dim">Joined</dt><dd class="text-fg">{@render when(user.created_at, '—')}</dd></div>
          <div class="flex items-center gap-1.5"><dt class="text-dim">Last seen</dt><dd class="text-fg">{@render when(user.last_seen, 'Never')}</dd></div>
          <div class="flex items-center gap-1.5">
            <dt class="text-dim">Live connections</dt>
            <dd class="inline-flex items-center gap-1.5 font-mono text-fg">
              {#if detail.connections > 0}<span class="status-dot text-accent" data-live="true"></span>{/if}{detail.connections}
            </dd>
          </div>
          <div class="flex items-center gap-1.5"><dt class="text-dim">Sign-in</dt><dd class="text-fg">{titleCase(user.auth_provider || 'local')}</dd></div>
          <div class="flex items-center gap-1"><dt class="text-dim">ID</dt><dd class="inline-flex items-center"><code class="font-mono text-[11.5px] text-fg" title={user.id}>{truncateMiddle(user.id, 6)}</code><CopyButton text={user.id} label="Copy user ID" size={12} /></dd></div>
        </dl>
      </div>
      <Button variant="outline" size="sm" icon="refresh" class="self-start" loading={loading} onclick={load}>Refresh</Button>
    </header>

    {#if restriction}<Alert tone="info" class="mb-6">{restriction}</Alert>{/if}

    <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
      <Card title="Plan and email" icon="star">
        {#if canManage}
          <form class="flex flex-col gap-3 sm:flex-row sm:items-end" onsubmit={savePlan}>
            <Select label="Plan" bind:value={planChoice} class="flex-1">
              <option value="">No plan</option>
              {#each adminState.plans as plan (plan.id)}
                <option value={plan.id}>{plan.name}{plan.is_active ? '' : ' (inactive)'} — {plan.max_devices} devices · {plan.max_clipboard_history.toLocaleString()} entries</option>
              {/each}
            </Select>
            <Button type="submit" variant="secondary" loading={busy === 'plan'} disabled={planChoice === (user.subscription_plan_id ?? '')}>Save plan</Button>
          </form>
        {:else}
          <p class="text-[13px] text-muted">Plan</p>
          <p class="mt-0.5 text-sm font-medium text-fg">{user.subscription_plan_name ?? 'No plan'}</p>
        {/if}

        <div class="mt-5 border-t border-border pt-4">
          <div class="flex items-center justify-between gap-3">
            <div class="min-w-0">
              <p class="text-[13px] font-medium text-fg">Email</p>
              <p class="truncate text-[13px] text-muted">{user.email || 'No email address'}</p>
            </div>
            {#if user.email}
              {#if user.email_verified}<Badge tone="mint" icon="check">Verified</Badge>{:else}<Badge tone="gold">Unverified</Badge>{/if}
            {/if}
          </div>
          {#if canManage && user.email && !user.email_verified}
            <div class="mt-3 flex flex-wrap gap-2">
              <Button variant="outline" size="xs" icon="check" loading={busy === 'verify'} onclick={verifyEmail}>Mark as verified</Button>
              <Button variant="outline" size="xs" icon="send" loading={busy === 'resend'} onclick={resendVerification}>Resend verification email</Button>
            </div>
          {/if}
        </div>
      </Card>

      <Card title="Security" description="Second factors and sessions" icon="shield-check">
        <dl class="divide-y divide-border text-[13px]">
          <div class="flex items-center justify-between pb-2.5"><dt class="text-muted">Authenticator app</dt><dd class="font-medium text-fg">{detail.mfa.totp ? 'Yes' : 'No'}</dd></div>
          <div class="flex items-center justify-between py-2.5"><dt class="text-muted">Passkeys</dt><dd class="font-mono text-fg">{detail.mfa.passkeys}</dd></div>
          <div class="flex items-center justify-between py-2.5">
            <dt class="text-muted">Recovery codes left</dt>
            <dd class="font-mono {detail.mfa.enabled && detail.mfa.recovery_codes_remaining <= 2 ? 'text-warning' : 'text-fg'}">{detail.mfa.recovery_codes_remaining}</dd>
          </div>
          <div class="flex items-center justify-between pt-2.5"><dt class="text-muted">Two-factor authentication</dt><dd class="text-fg">{detail.mfa.required ? 'Required' : 'Optional'} for this account</dd></div>
        </dl>
        {#if (canResetMfa && detail.mfa.enabled) || canRevoke}
          <div class="mt-4 flex flex-wrap gap-2 border-t border-border pt-4">
            {#if canResetMfa && detail.mfa.enabled}
              <ConfirmAction label="Reset 2FA" icon="shield" size="xs" confirmLabel="Reset 2FA" prompt="Remove every second factor?" onconfirm={resetMfa} />
            {/if}
            {#if canRevoke}
              <ConfirmAction label="Sign out everywhere" icon="log-out" size="xs" confirmLabel="Sign out" prompt="End every session?" onconfirm={revokeSessions} />
            {/if}
          </div>
          {#if canResetMfa && detail.mfa.enabled}
            <p class="mt-2 text-xs text-dim">Resetting removes their authenticator app, passkeys and recovery codes and signs them out; they set up 2FA again when they next sign in.</p>
          {/if}
        {/if}
      </Card>

      <Card title="Status" icon={user.suspended_at ? 'lock' : 'unlock'}>
        {#if user.suspended_at}
          <p class="flex flex-wrap items-center gap-2 text-[13px] text-muted">
            <Badge tone="rose" icon="lock">Suspended</Badge>
            <span>{@render when(user.suspended_at, '')}</span>
          </p>
          <dl class="mt-4 text-[13px]">
            <dt class="text-xs text-dim">Reason, visible to staff only</dt>
            <dd class="mt-1 whitespace-pre-wrap break-words text-fg">{detail.suspended_reason || 'No reason given.'}</dd>
          </dl>
          {#if canSuspend}
            <div class="mt-4"><Button variant="outline" size="sm" icon="unlock" loading={busy === 'unsuspend'} onclick={unsuspend}>Reinstate</Button></div>
          {/if}
        {:else}
          <p class="flex flex-wrap items-center gap-2 text-[13px] text-muted"><Badge tone="mint" dot>Active</Badge> Can sign in and sync.</p>
          {#if canSuspend}
            <div class="mt-4"><Button variant="outline" size="sm" icon="lock" onclick={openSuspend}>Suspend…</Button></div>
            <p class="mt-2 text-xs text-dim">Suspending signs them out everywhere and blocks sign-in until you reinstate them. Their data is kept.</p>
          {/if}
        {/if}
      </Card>

      <Card title="Role" description="Access to the admin console" icon="users">
        {#if canSetRole}
          <form class="flex flex-col gap-3 sm:flex-row sm:items-end" onsubmit={saveRole}>
            <Select label="Role" bind:value={roleChoice} class="flex-1">
              {#each ROLES as r (r.value)}
                <option value={r.value}>{r.label}</option>
              {/each}
            </Select>
            <Button type="submit" variant="secondary" loading={busy === 'role'} disabled={roleChoice === user.role}>Save role</Button>
          </form>
          <p class="mt-2 text-xs text-dim">{ROLES.find((r) => r.value === roleChoice)?.description} The server always keeps at least one owner.</p>
        {:else}
          <RoleBadge role={user.role} />
          <p class="mt-2 text-[13px] text-muted">{ROLES.find((r) => r.value === user.role)?.description}</p>
          <p class="mt-2 text-xs text-dim">{isSelf ? 'You can’t change your own role.' : 'Only owners can change roles.'}</p>
        {/if}
      </Card>

      <Card title="Devices" description="{detail.devices.length} paired · {onlineDevices} online" icon="monitor" padded={false} class="lg:col-span-2">
        {#if detail.devices.length === 0}
          <div class="p-5"><EmptyState icon="smartphone" title="No devices" description="This account has not paired a device yet." compact /></div>
        {:else}
          <div class="overflow-x-auto">
            <table class="tbl min-w-[640px]">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Status</th>
                  <th>Last seen</th>
                  <th>Added</th>
                </tr>
              </thead>
              <tbody>
                {#each detail.devices as device (device.id)}
                  {@const s = deviceStatus(device)}
                  <tr>
                    <td>
                      <span class="flex items-center gap-2.5">
                        <span class={device.online ? 'text-fg' : 'text-dim'}><Icon name="monitor" size={15} /></span>
                        <span class="font-medium text-fg">{device.name}</span>
                      </span>
                    </td>
                    <td><Badge tone={s.tone} dot={s.tone === 'mint' || s.tone === 'neutral'} live={device.online}>{s.label}</Badge></td>
                    <td class="whitespace-nowrap text-muted">{#if device.online}Connected now{:else}{@render when(device.last_seen, 'Never')}{/if}</td>
                    <td class="whitespace-nowrap text-muted">{@render when(device.created_at, '—')}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      </Card>

      <Card title="Recent activity" description="Sign-ins, security changes and staff actions" icon="activity" padded={false} class="lg:col-span-2">
        {#snippet actions()}
          <a href="#/admin/audit?user={user.id}" class="inline-flex items-center gap-1 text-[12px] font-medium text-muted transition-colors duration-150 hover:text-fg">
            Full audit log <Icon name="arrow-right" size={12} />
          </a>
        {/snippet}
        {#if detail.recent_activity.length === 0}
          <div class="p-5"><EmptyState icon="activity" title="No activity yet" description="Sign-ins, security changes and staff actions on this account will show up here." compact /></div>
        {:else}
          <ul class="divide-y divide-border">
            {#each detail.recent_activity as entry (entry.id)}
              <li class="flex flex-col gap-1.5 px-5 py-3 sm:flex-row sm:items-center sm:gap-3">
                <Badge tone={auditActionTone(entry.action)} title={entry.action}>{auditActionLabel(entry.action)}</Badge>
                <p class="min-w-0 flex-1 truncate text-[13px] text-muted">
                  {#if entry.user_id === user.id}by them{:else if entry.user_id}by {@render userLink(entry.user_id, entry.username)}{/if}
                  {#if entry.target_user_id && entry.target_user_id !== user.id}<span class="text-dim"> → </span>{@render userLink(entry.target_user_id, entry.target_username)}{/if}
                </p>
                {#if entry.ip_address}<span class="shrink-0 font-mono text-[11.5px] text-dim">{entry.ip_address}</span>{/if}
                <span class="shrink-0 text-[12px] text-muted">{@render when(entry.created_at, '')}</span>
              </li>
            {/each}
          </ul>
        {/if}
      </Card>

      {#if canDelete}
        <Card title="Danger zone" icon="alert-triangle" class="lg:col-span-2">
          <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div class="min-w-0">
              <p class="text-sm font-medium text-fg">Delete this account</p>
              <p class="mt-0.5 text-[13px] text-muted">Removes {handle}, their devices and their clipboard history for good. Suspending can be undone; deleting can’t.</p>
            </div>
            <ConfirmAction label="Delete user" variant="danger-soft" confirmLabel="Delete forever" prompt="This can’t be undone." loading={busy === 'delete'} onconfirm={remove} />
          </div>
        </Card>
      {/if}
    </div>
  {/if}
</AdminGate>

<Dialog bind:open={suspendOpen} title="Suspend {handle}" description="They are signed out everywhere and can’t sign in until you reinstate them. Their data is kept." size="sm">
  <form id="suspend-form" onsubmit={suspend}>
    <TextArea label="Reason" bind:value={suspendReason} maxlength={500} rows={3} placeholder="For example: spam reported by several members" hint="Optional. Visible to staff only." />
  </form>
  {#snippet footer()}
    <Button variant="ghost" onclick={() => (suspendOpen = false)}>Cancel</Button>
    <Button type="submit" form="suspend-form" variant="danger" icon="lock" loading={busy === 'suspend'}>Suspend account</Button>
  {/snippet}
</Dialog>
