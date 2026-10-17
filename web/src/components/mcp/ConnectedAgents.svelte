<script lang="ts">
  import { onMount } from 'svelte';
  import { ApiError } from '../../lib/api';
  import { createClock } from '../../lib/clock.svelte';
  import { absoluteTime, relativeTime, titleCase } from '../../lib/format';
  import { errorMessage } from '../../lib/mfa';
  import { knownScopes, listAgentGrants, revokeAgentGrant, SCOPE_INFO, scopeLabel, type AgentGrant } from '../../lib/oauth';
  import { toast } from '../../lib/stores/toast.svelte';
  import Alert from '../ui/Alert.svelte';
  import Badge from '../ui/Badge.svelte';
  import Button from '../ui/Button.svelte';
  import Card from '../ui/Card.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import EmptyState from '../ui/EmptyState.svelte';
  import IconTile from '../ui/IconTile.svelte';
  import Skeleton from '../ui/Skeleton.svelte';

  // The agents the user let sign in (OAuth grants), and revoking them

  const clock = createClock();

  let grants = $state<AgentGrant[] | null>(null);
  let loading = $state(false);
  let loadError = $state('');
  /** The agent the revoke dialog asks about. */
  let revoking = $state<AgentGrant | null>(null);
  let revokeBusy = $state(false);

  onMount(load);

  async function load() {
    loading = true;
    try {
      grants = await listAgentGrants();
      loadError = '';
    } catch (err) {
      loadError = errorMessage(err);
    } finally {
      loading = false;
    }
  }

  function nameOf(grant: AgentGrant): string {
    return grant.agent_name || 'Unnamed agent';
  }

  function deviceStatus(status: string): { label: string; tone: 'mint' | 'gold' | 'neutral' } {
    if (status === 'approved') return { label: 'Paired', tone: 'mint' };
    if (status === 'pending') return { label: 'Waiting for pairing', tone: 'gold' };
    return { label: titleCase(status), tone: 'neutral' };
  }

  /** Why a grant shows as signed out, and what the user can do about it. */
  function signedOutNote(grant: AgentGrant): string {
    const why =
      "Its sign-in ended: you signed out everywhere after connecting it (for example by changing your password), or it wasn't used for 30 days.";
    return grant.device
      ? `${why} Its device stays paired, so it can sign in again without pairing; then this entry is replaced. Revoke it to remove the device.`
      : `${why} It can sign in again from the agent. Revoke it to remove it from this list.`;
  }

  async function revoke() {
    const grant = revoking;
    if (!grant) return;
    revokeBusy = true;
    try {
      await revokeAgentGrant(grant.id);
      toast.success('Agent revoked', `${nameOf(grant)} is signed out${grant.device ? ' and its device was removed' : ''}.`);
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 404)) {
        toast.error("Couldn't revoke the agent", errorMessage(err));
        revokeBusy = false;
        return;
      }
      // Already revoked, here or by the agent signing out
      toast.info('Agent already revoked', `${nameOf(grant)} no longer has access.`);
    }
    grants = grants?.filter((g) => g.id !== grant.id) ?? null;
    revokeBusy = false;
    revoking = null;
  }

  function closeDialog() {
    if (!revokeBusy) revoking = null;
  }
</script>

<Card title="Connected agents" description="AI agents you allowed to use your account. Revoking one signs it out and removes its device." icon="sparkles">
  {#snippet actions()}
    <Button variant="outline" size="sm" icon="refresh" loading={loading && grants !== null} onclick={load}>Refresh</Button>
  {/snippet}

  {#if loadError && !grants}
    <div class="flex flex-col items-start gap-3">
      <Alert tone="danger">{loadError}</Alert>
      <Button variant="secondary" size="sm" icon="refresh" onclick={load}>Try again</Button>
    </div>
  {:else if !grants}
    <div class="flex flex-col gap-4" aria-hidden="true">
      {#each Array(2) as _, i (i)}
        <div class="flex items-center gap-3">
          <Skeleton class="h-9 w-9" />
          <div class="flex-1"><Skeleton class="mb-2 h-3 w-1/3" /><Skeleton class="h-3 w-2/3" /></div>
        </div>
      {/each}
    </div>
  {:else if grants.length === 0}
    <EmptyState
      compact
      icon="sparkles"
      title="No agents connected yet"
      description="Set one up below. When it signs in, you approve it in your browser and it shows up here."
    />
  {:else}
    <ul class="divide-y divide-border rounded-md border border-border">
      {#each grants as grant (grant.id)}
        {@const scopes = knownScopes(grant.scopes)}
        <li class="flex flex-col gap-3 p-4 sm:flex-row sm:items-start">
          <div class="flex min-w-0 flex-1 items-start gap-3">
            <IconTile icon="sparkles" />
            <div class="min-w-0 flex-1">
              <p class="flex flex-wrap items-center gap-2 text-sm font-medium text-fg">
                <bdi class="min-w-0 break-words">{nameOf(grant)}</bdi>
                {#if grant.status === 'active'}
                  <Badge tone="mint" dot>Active</Badge>
                {:else}
                  <Badge tone="neutral" dot>Signed out</Badge>
                {/if}
              </p>
              <p class="mt-0.5 text-[13px] text-muted">
                {grant.client_name ?? grant.client_id}{grant.agent_name ? ' · name reported by the agent' : ''}
              </p>

              <ul class="mt-2.5 flex flex-wrap gap-1.5" aria-label="Allowed">
                {#each scopes as scope (scope)}
                  <li><Badge icon={SCOPE_INFO[scope].icon} title={scopeLabel(scope)}>{SCOPE_INFO[scope].short}</Badge></li>
                {/each}
              </ul>

              <dl class="mt-2.5 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
                <dt class="text-dim">Device</dt>
                <dd class="flex min-w-0 flex-wrap items-center gap-1.5 text-muted">
                  {#if grant.device}
                    {@const status = deviceStatus(grant.device.status)}
                    <span class="break-words text-fg">{grant.device.name || 'Unnamed device'}</span>
                    <Badge tone={status.tone}>{status.label}</Badge>
                  {:else}
                    Not registered yet
                  {/if}
                </dd>
                <dt class="text-dim">Connected</dt>
                <dd class="text-muted"><time datetime={grant.created_at} title={absoluteTime(grant.created_at)}>{relativeTime(grant.created_at, clock.now)}</time></dd>
                <dt class="text-dim">Last used</dt>
                <dd class="text-muted">
                  {#if grant.last_used_at}
                    <time datetime={grant.last_used_at} title={absoluteTime(grant.last_used_at)}>{relativeTime(grant.last_used_at, clock.now)}</time>
                  {:else}
                    Never
                  {/if}
                </dd>
              </dl>

              {#if grant.status === 'signed_out'}
                <p class="mt-2.5 text-xs leading-relaxed text-muted">{signedOutNote(grant)}</p>
              {/if}
            </div>
          </div>
          <div class="shrink-0 sm:pl-3">
            <Button variant="outline" size="sm" icon="trash" class="hover:border-red-200 hover:text-danger" aria-label="Revoke {nameOf(grant)}" onclick={() => (revoking = grant)}>
              Revoke
            </Button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</Card>

<Dialog open={revoking !== null} title="Revoke this agent?" size="sm" onclose={closeDialog}>
  {#if revoking}
    <div class="flex flex-col gap-3 text-[13px] leading-relaxed text-muted">
      <p><bdi class="font-medium text-fg">{nameOf(revoking)}</bdi> is signed out and can't use your account anymore.</p>
      {#if revoking.device}
        <p>
          Its device, <span class="font-medium text-fg">{revoking.device.name || 'Unnamed device'}</span>, is removed from your account, and your other
          devices rotate the encryption key so it can't read anything new.
        </p>
      {:else}
        <p>It hasn't registered a device yet, so there's no device to remove.</p>
      {/if}
      <p>To use it again, sign it in and pair it again.</p>
    </div>
  {/if}
  {#snippet footer()}
    <Button variant="ghost" disabled={revokeBusy} onclick={closeDialog}>Cancel</Button>
    <Button variant="danger" icon="trash" loading={revokeBusy} onclick={revoke}>Revoke access</Button>
  {/snippet}
</Dialog>
