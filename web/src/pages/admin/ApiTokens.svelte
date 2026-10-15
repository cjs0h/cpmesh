<script lang="ts">
  import { onMount } from 'svelte';
  import { push } from 'svelte-spa-router';
  import { can, userState } from '../../lib/stores/user.svelte';
  import {
    adminCreateApiToken,
    adminRevokeApiToken,
    adminState,
    API_TOKEN_SCOPES,
    apiTokenStatus,
    errorMessage,
    fetchApiTokens,
    isMfaRequired,
    type ApiToken,
    type CreatedApiToken,
  } from '../../lib/stores/admin.svelte';
  import { toast } from '../../lib/stores/toast.svelte';
  import { createClock } from '../../lib/clock.svelte';
  import { absoluteTime, relativeTime } from '../../lib/format';
  import Icon from '../../components/Icon.svelte';
  import Alert from '../../components/ui/Alert.svelte';
  import Badge from '../../components/ui/Badge.svelte';
  import Button from '../../components/ui/Button.svelte';
  import Card from '../../components/ui/Card.svelte';
  import ConfirmAction from '../../components/ui/ConfirmAction.svelte';
  import CopyButton from '../../components/ui/CopyButton.svelte';
  import Dialog from '../../components/ui/Dialog.svelte';
  import EmptyState from '../../components/ui/EmptyState.svelte';
  import Field from '../../components/ui/Field.svelte';
  import Select from '../../components/ui/Select.svelte';
  import Skeleton from '../../components/ui/Skeleton.svelte';
  import AdminGate from '../../components/admin/AdminGate.svelte';

  const clock = createClock();
  const allowed = $derived(can('manage_api_tokens'));
  let loaded = $state(false);
  let loading = $state(false);
  let loadError = $state('');

  let dialogOpen = $state(false);
  let name = $state('');
  let scopes = $state<string[]>(API_TOKEN_SCOPES.map((s) => s.value));
  let expiry = $state('90');
  let creating = $state(false);
  let createError = $state('');
  let created = $state<CreatedApiToken | null>(null);

  onMount(() => {
    if (!userState.isAdmin) {
      push('/');
      return;
    }
    if (can('manage_api_tokens')) load();
  });

  async function load() {
    loading = true;
    try {
      await fetchApiTokens();
      loaded = true;
      loadError = '';
    } catch (err) {
      if (!isMfaRequired(err)) loadError = errorMessage(err);
    } finally {
      loading = false;
    }
  }

  const activeCount = $derived(adminState.apiTokens.filter((t) => apiTokenStatus(t, clock.now) === 'active').length);

  function startCreate() {
    name = '';
    scopes = API_TOKEN_SCOPES.map((s) => s.value);
    expiry = '90';
    createError = '';
    created = null;
    dialogOpen = true;
  }

  // The secret only lives in this dialog: forget it once it closes
  function closeDialog() {
    dialogOpen = false;
    created = null;
  }

  async function create(e: SubmitEvent) {
    e.preventDefault();
    createError = '';
    if (scopes.length === 0) {
      createError = 'Choose at least one scope.';
      return;
    }
    creating = true;
    try {
      created = await adminCreateApiToken({ name: name.trim(), scopes, expires_in_days: expiry === 'never' ? null : Number(expiry) });
      toast.success('API token created', 'Copy it now: it is shown only once.');
    } catch (err) {
      if (!isMfaRequired(err)) createError = errorMessage(err);
    } finally {
      creating = false;
    }
  }

  async function revoke(token: ApiToken) {
    try {
      await adminRevokeApiToken(token.id);
      toast.success('API token revoked', `“${token.name}” stops working immediately.`);
    } catch (err) {
      if (!isMfaRequired(err)) toast.error('Could not revoke the token', errorMessage(err));
    }
  }

  const statusBadge = {
    active: { tone: 'mint', label: 'Active' },
    expired: { tone: 'gold', label: 'Expired' },
    revoked: { tone: 'neutral', label: 'Revoked' },
  } as const;
</script>

{#snippet when(value: string | null, empty: string)}
  {#if value}
    <time datetime={value} title={absoluteTime(value)}>{relativeTime(value, clock.now)}</time>
  {:else}
    <span class="text-dim">{empty}</span>
  {/if}
{/snippet}

<AdminGate onunlock={load}>
  {#if !allowed}
    <EmptyState icon="key" title="API tokens are managed by admins" description="Your role can’t view or create API tokens. Ask an admin or owner if automation needs one." />
  {:else}
    <div class="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
      <p class="max-w-2xl text-[13px] text-muted">
        Tokens let automation such as the Release workflow publish releases and download links. They only work on those admin routes and act as the admin who created them.
      </p>
      <Button icon="plus" size="sm" class="shrink-0" onclick={startCreate}>New token</Button>
    </div>

    {#if loadError}
      <Alert tone="danger" title="Could not load API tokens" class="mb-4">
        {loadError}
        <Button variant="link" class="ml-1" onclick={load}>Try again</Button>
      </Alert>
    {/if}

    <Card padded={false}>
      {#if !loaded}
        <div class="flex flex-col gap-4 p-5" aria-busy="true">
          {#each Array(3) as _, i (i)}
            <div class="flex items-center gap-4"><Skeleton class="h-3 w-32" /><Skeleton class="h-3 w-24" /><Skeleton class="h-5 w-24" rounded="rounded-full" /><Skeleton class="ml-auto h-3 w-16" /></div>
          {/each}
        </div>
      {:else if adminState.apiTokens.length === 0}
        <div class="p-5">
          <EmptyState icon="key" title="No API tokens" description="Create one for the Release workflow: it publishes installers and app releases here when a version is tagged." compact>
            <Button icon="plus" size="sm" onclick={startCreate}>Create a token</Button>
          </EmptyState>
        </div>
      {:else}
        <div class="overflow-x-auto">
          <table class="tbl min-w-[1000px] {loading ? 'opacity-60' : ''}">
            <thead>
              <tr>
                <th>Name</th>
                <th>Token</th>
                <th>Scopes</th>
                <th>Created by</th>
                <th>Created</th>
                <th>Last used</th>
                <th>Expires</th>
                <th>Status</th>
                <th class="text-right"><span class="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {#each adminState.apiTokens as token (token.id)}
                {@const status = apiTokenStatus(token, clock.now)}
                <tr class={status === 'active' ? '' : 'opacity-60'}>
                  <td class="font-medium text-fg">{token.name}</td>
                  <td><code class="font-mono text-[12px] text-muted">{token.token_prefix}…</code></td>
                  <td>
                    <span class="flex flex-wrap gap-1">
                      {#each token.scopes as scope (scope)}<Badge tone="neutral">{scope}</Badge>{/each}
                    </span>
                  </td>
                  <td>
                    {#if token.username}
                      <a href="#/admin/users/{token.user_id}" class="text-fg hover:underline">@{token.username}</a>
                    {:else}
                      <span class="text-dim">Deleted user</span>
                    {/if}
                  </td>
                  <td class="whitespace-nowrap text-muted">{@render when(token.created_at, '—')}</td>
                  <td class="whitespace-nowrap text-muted">{@render when(token.last_used_at, 'Never')}</td>
                  <td class="whitespace-nowrap text-muted">
                    {#if token.expires_at}
                      <time datetime={token.expires_at} title={absoluteTime(token.expires_at)}>{new Date(token.expires_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })}</time>
                    {:else}
                      <span class="text-dim">Never</span>
                    {/if}
                  </td>
                  <td><Badge tone={statusBadge[status].tone} dot={status === 'active'}>{statusBadge[status].label}</Badge></td>
                  <td class="text-right">
                    {#if status !== 'revoked'}
                      <ConfirmAction size="xs" variant="ghost" label="Revoke" icon="x" confirmLabel="Revoke" prompt="Revoke this token?" onconfirm={() => revoke(token)} />
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
        <p class="border-t border-border bg-bg-deep px-5 py-3 text-[12.5px] text-muted">{activeCount} active of {adminState.apiTokens.length}</p>
      {/if}
    </Card>
  {/if}
</AdminGate>

<Dialog bind:open={dialogOpen} title={created ? 'Copy your new token' : 'New API token'} description={created ? 'This is the only time it is shown.' : 'For automation such as the Release workflow.'} onclose={() => (created = null)}>
  {#if created}
    <div class="flex flex-col gap-4">
      <Alert tone="warning" title="Store it somewhere safe">You won’t be able to see this token again. If it is lost, revoke it and create a new one.</Alert>
      <div class="flex items-center gap-2 rounded-md border border-border bg-bg-deep px-3 py-2.5">
        <code class="min-w-0 flex-1 break-all font-mono text-[12.5px] text-fg">{created.token}</code>
        <CopyButton text={created.token} label="Copy token" />
      </div>
      <div class="flex items-start gap-2.5 text-[13px] text-muted">
        <span class="mt-0.5 text-dim"><Icon name="github" size={15} /></span>
        <p>Add it as the <code class="font-mono text-[12px] text-fg">CPMESH_ADMIN_TOKEN</code> secret of the GitHub repository; the Release workflow uses it to publish releases.</p>
      </div>
    </div>
  {:else}
    <form id="token-form" class="flex flex-col gap-4" onsubmit={create}>
      {#if createError}<Alert tone="danger">{createError}</Alert>{/if}
      <Field label="Name" bind:value={name} required maxlength={100} placeholder="GitHub release workflow" hint="Helps you recognise it later." />
      <fieldset class="flex flex-col gap-2">
        <legend class="mb-1.5 text-[13px] font-medium text-fg">Scopes</legend>
        {#each API_TOKEN_SCOPES as scope (scope.value)}
          <label class="flex cursor-pointer items-start gap-2.5 rounded-md border border-border px-3 py-2.5 transition-colors duration-150 hover:border-border-strong">
            <input type="checkbox" class="mt-0.5 h-4 w-4 accent-ink" value={scope.value} bind:group={scopes} />
            <span>
              <code class="block font-mono text-[12.5px] text-fg">{scope.label}</code>
              <span class="text-xs text-dim">{scope.description}</span>
            </span>
          </label>
        {/each}
      </fieldset>
      <Select label="Expires" bind:value={expiry} hint="Tokens that never expire are convenient but riskier.">
        <option value="30">In 30 days</option>
        <option value="90">In 90 days</option>
        <option value="180">In 180 days</option>
        <option value="365">In a year</option>
        <option value="never">Never</option>
      </Select>
    </form>
  {/if}
  {#snippet footer()}
    {#if created}
      <Button onclick={closeDialog}>Done</Button>
    {:else}
      <Button variant="ghost" onclick={closeDialog}>Cancel</Button>
      <Button type="submit" form="token-form" icon="key" loading={creating} disabled={!name.trim() || scopes.length === 0}>Create token</Button>
    {/if}
  {/snippet}
</Dialog>
