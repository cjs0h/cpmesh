<script lang="ts">
  import { onMount } from 'svelte';
  import { setTokens } from '../../lib/auth';
  import { absoluteTime, relativeTime } from '../../lib/format';
  import {
    errorMessage,
    getMfaStatus,
    isCancellation,
    passkeysSupported,
    regenerateRecoveryCodes,
    removePasskey,
    removeTotp,
    renamePasskey,
    sessionTransport,
    type EnrollResult,
    type MfaStatus,
    type Passkey,
  } from '../../lib/mfa';
  import { toast } from '../../lib/stores/toast.svelte';
  import { fetchCurrentUser, userState } from '../../lib/stores/user.svelte';
  import Alert from '../ui/Alert.svelte';
  import Badge from '../ui/Badge.svelte';
  import Button from '../ui/Button.svelte';
  import Card from '../ui/Card.svelte';
  import ConfirmAction from '../ui/ConfirmAction.svelte';
  import Dialog from '../ui/Dialog.svelte';
  import Field from '../ui/Field.svelte';
  import IconTile from '../ui/IconTile.svelte';
  import Skeleton from '../ui/Skeleton.svelte';
  import PasskeySetup from './PasskeySetup.svelte';
  import RecoveryCodes from './RecoveryCodes.svelte';
  import TotpSetup from './TotpSetup.svelte';

  // Settings section: authenticator app, passkeys and recovery codes

  let status = $state<MfaStatus | null>(null);
  let loadError = $state('');
  let setup = $state<'totp' | 'passkey' | null>(null);
  /** Recovery codes to show once, after the first factor or a regeneration. */
  let newCodes = $state<string[] | null>(null);
  let renaming = $state<string | null>(null);
  let renameValue = $state('');
  let renameBusy = $state(false);

  const supported = passkeysSupported();
  const account = $derived(userState.email || userState.username);
  const canAddPasskey = $derived(Boolean(status?.passkeys_available) && supported);

  onMount(load);

  async function load() {
    try {
      status = await getMfaStatus(sessionTransport);
      loadError = '';
    } catch (err) {
      loadError = errorMessage(err);
    }
  }

  async function refresh() {
    await Promise.all([load(), fetchCurrentUser()]);
  }

  async function enrolled(result: EnrollResult, what: string) {
    // Adding a factor upgrades the session: keep the new pair
    setTokens(result.access_token, result.refresh_token);
    setup = null;
    if (result.recovery_codes?.length) newCodes = result.recovery_codes;
    toast.success(`${what} added`);
    await refresh();
  }

  async function act(action: () => Promise<unknown>, success: string, failure: string) {
    try {
      await action();
      toast.success(success);
      await refresh();
    } catch (err) {
      if (!isCancellation(err)) toast.error(failure, errorMessage(err));
    }
  }

  async function regenerate() {
    try {
      newCodes = await regenerateRecoveryCodes();
      await refresh();
    } catch (err) {
      if (!isCancellation(err)) toast.error("Couldn't create new recovery codes", errorMessage(err));
    }
  }

  function startRename(passkey: Passkey) {
    renaming = passkey.id;
    renameValue = passkey.name;
  }

  async function saveRename(e: Event, passkey: Passkey) {
    e.preventDefault();
    const name = renameValue.trim();
    if (!name || name === passkey.name) {
      renaming = null;
      return;
    }
    renameBusy = true;
    try {
      await renamePasskey(passkey.id, name);
      renaming = null;
      await load();
    } catch (err) {
      toast.error("Couldn't rename the passkey", errorMessage(err));
    } finally {
      renameBusy = false;
    }
  }
</script>

<Card title="Two-factor authentication" description="A second step after your password or single sign-on" icon="shield-check" accent="mint">
  {#snippet actions()}
    {#if status}
      <Badge tone={status.enabled ? 'mint' : 'gold'} dot>{status.enabled ? 'On' : 'Off'}</Badge>
    {/if}
  {/snippet}

  {#if loadError && !status}
    <div class="flex flex-col items-start gap-3">
      <Alert tone="danger">{loadError}</Alert>
      <Button variant="secondary" size="sm" icon="refresh" onclick={load}>Try again</Button>
    </div>
  {:else if !status}
    <div class="flex flex-col gap-4" aria-hidden="true">
      {#each Array(3) as _, i (i)}
        <div class="flex items-center gap-3">
          <Skeleton class="h-9 w-9" />
          <div class="flex-1"><Skeleton class="mb-2 h-3 w-1/3" /><Skeleton class="h-3 w-2/3" /></div>
        </div>
      {/each}
    </div>
  {:else}
    <div class="flex flex-col gap-5">
      {#if status.required && !status.enabled}
        <Alert tone="warning">Two-factor authentication is required for your account. Set up an authenticator app or a passkey.</Alert>
      {:else if status.required}
        <p class="text-[13px] text-muted">Required for your account: keep at least one method set up.</p>
      {/if}

      <ul class="divide-y divide-border rounded-md border border-border">
        <!-- Authenticator app -->
        <li class="flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
          <div class="flex min-w-0 flex-1 items-start gap-3">
            <IconTile icon="smartphone" />
            <div class="min-w-0">
              <p class="flex flex-wrap items-center gap-2 text-sm font-medium text-fg">
                Authenticator app
                {#if status.totp}<Badge tone="mint">Set up</Badge>{/if}
              </p>
              <p class="mt-0.5 text-[13px] text-muted">6-digit codes from an app. The desktop app and AI agents (MCP) use these too.</p>
            </div>
          </div>
          <div class="shrink-0 sm:pl-3">
            {#if status.totp}
              <ConfirmAction label="Remove" confirmLabel="Remove" prompt="Remove the app?" onconfirm={() => act(removeTotp, 'Authenticator app removed', "Couldn't remove the authenticator app")} />
            {:else}
              <Button size="sm" onclick={() => (setup = 'totp')}>Set up</Button>
            {/if}
          </div>
        </li>

        <!-- Passkeys -->
        <li class="flex flex-col gap-3 p-4">
          <div class="flex flex-col gap-3 sm:flex-row sm:items-center">
            <div class="flex min-w-0 flex-1 items-start gap-3">
              <IconTile icon="key" />
              <div class="min-w-0">
                <p class="flex flex-wrap items-center gap-2 text-sm font-medium text-fg">
                  Passkeys
                  {#if status.passkeys.length}<Badge tone="mint">{status.passkeys.length}</Badge>{/if}
                </p>
                <p class="mt-0.5 text-[13px] text-muted">
                  {#if !status.passkeys_available}
                    Not enabled on this server.
                  {:else if !supported}
                    This browser doesn't support passkeys.
                  {:else}
                    Touch ID, Face ID, Windows Hello, your phone or a security key, in the browser.
                  {/if}
                </p>
              </div>
            </div>
            {#if canAddPasskey}
              <div class="shrink-0 sm:pl-3">
                <Button size="sm" variant={status.passkeys.length ? 'secondary' : 'primary'} icon="plus" onclick={() => (setup = 'passkey')}>Add passkey</Button>
              </div>
            {/if}
          </div>

          {#if status.passkeys.length}
            <ul class="flex flex-col gap-2 sm:pl-12">
              {#each status.passkeys as passkey (passkey.id)}
                <li class="flex items-center gap-2 rounded-md border border-border bg-bg-deep px-3 py-2.5">
                  {#if renaming === passkey.id}
                    <form class="flex flex-1 items-center gap-2" onsubmit={(e) => saveRename(e, passkey)}>
                      <Field bind:value={renameValue} aria-label="Passkey name" maxlength={60} class="flex-1" autocomplete="off" />
                      <Button type="submit" size="sm" loading={renameBusy}>Save</Button>
                      <Button variant="ghost" size="sm" disabled={renameBusy} onclick={() => (renaming = null)}>Cancel</Button>
                    </form>
                  {:else}
                    <div class="min-w-0 flex-1">
                      <p class="flex flex-wrap items-center gap-2 text-sm text-fg">
                        <span class="truncate">{passkey.name}</span>
                        {#if passkey.backup_eligible}<Badge title="Saved in a passkey manager that syncs across your devices">Synced</Badge>{/if}
                      </p>
                      <p class="mt-0.5 text-xs text-dim">
                        <span title={absoluteTime(passkey.created_at)}>Added {relativeTime(passkey.created_at)}</span>
                        ·
                        {#if passkey.last_used_at}
                          <span title={absoluteTime(passkey.last_used_at)}>last used {relativeTime(passkey.last_used_at)}</span>
                        {:else}
                          never used
                        {/if}
                      </p>
                    </div>
                    <span class="inline-flex shrink-0 items-center gap-1">
                      <Button variant="ghost" size="icon-sm" icon="edit" aria-label="Rename {passkey.name}" title="Rename" onclick={() => startRename(passkey)} />
                      <ConfirmAction
                        size="icon-sm"
                        variant="ghost"
                        label="Remove {passkey.name}"
                        title="Remove"
                        confirmLabel="Remove"
                        prompt="Remove?"
                        onconfirm={() => act(() => removePasskey(passkey.id), 'Passkey removed', "Couldn't remove the passkey")}
                      />
                    </span>
                  {/if}
                </li>
              {/each}
            </ul>
          {/if}
        </li>

        <!-- Recovery codes -->
        {#if status.enabled}
          <li class="flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
            <div class="flex min-w-0 flex-1 items-start gap-3">
              <IconTile icon="lock" />
              <div class="min-w-0">
                <p class="flex flex-wrap items-center gap-2 text-sm font-medium text-fg">
                  Recovery codes
                  <Badge tone={status.recovery_codes_remaining > 3 ? 'neutral' : 'gold'}>{status.recovery_codes_remaining} left</Badge>
                </p>
                <p class="mt-0.5 text-[13px] text-muted">One-time codes for when you can't use your app or passkey.</p>
              </div>
            </div>
            <div class="shrink-0 sm:pl-3">
              <ConfirmAction icon="refresh" label="New codes" confirmLabel="Replace" prompt="Replace all codes?" onconfirm={regenerate} />
            </div>
          </li>
        {/if}
      </ul>
    </div>
  {/if}
</Card>

<Dialog
  open={setup !== null}
  title={setup === 'totp' ? 'Set up an authenticator app' : 'Add a passkey'}
  description={setup === 'totp' ? 'Scan the QR code, then enter the code the app shows.' : 'Save a passkey on this device or a security key.'}
  size="sm"
  onclose={() => (setup = null)}
>
  {#if setup === 'totp'}
    <TotpSetup send={sessionTransport} onenrolled={(result) => enrolled(result, 'Authenticator app')} />
  {:else if setup === 'passkey'}
    <PasskeySetup send={sessionTransport} onenrolled={(result) => enrolled(result, 'Passkey')} />
  {/if}
</Dialog>

<Dialog open={newCodes !== null} title="Your new recovery codes" onclose={() => (newCodes = null)}>
  {#if newCodes}
    <RecoveryCodes
      codes={newCodes}
      {account}
      onconfirm={() => {
        newCodes = null;
      }}
    />
  {/if}
</Dialog>
