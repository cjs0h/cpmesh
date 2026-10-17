<script lang="ts">
  import { onMount } from 'svelte';
  import { setTokens, signInLocation } from '../../lib/auth';
  import { titleCase } from '../../lib/format';
  import { errorMessage, getMfaStatus, sessionTransport, verifyFactor, verifyMethods, type MfaMethod, type SessionTokens } from '../../lib/mfa';
  import { fetchCurrentUser, resetUserState, userState } from '../../lib/stores/user.svelte';
  import { disconnectWS } from '../../lib/ws';
  import Alert from '../ui/Alert.svelte';
  import Button from '../ui/Button.svelte';
  import Field from '../ui/Field.svelte';
  import Spinner from '../ui/Spinner.svelte';
  import VerifyFactor from './VerifyFactor.svelte';

  /**
   * "Confirm it's you": the second factor, or the password for accounts that have none
   * yet. Stores the refreshed session before reporting success.
   */
  interface Props {
    onconfirmed: () => void;
    oncancel: () => void;
  }

  let { onconfirmed, oncancel }: Props = $props();

  let loading = $state(true);
  let enabled = $state(false);
  let methods = $state<MfaMethod[]>([]);
  let hasPassword = $state(false);
  let password = $state('');
  let error = $state('');
  let busy = $state(false);
  let passwordForm = $state<HTMLFormElement | null>(null);

  // The form appears after the dialog opened, so focus it once it renders
  $effect(() => {
    passwordForm?.querySelector('input')?.focus();
  });

  onMount(async () => {
    try {
      const status = await getMfaStatus(sessionTransport);
      enabled = status.enabled;
      methods = verifyMethods(status);
      hasPassword = status.has_password;
    } catch {
      // Go by the profile instead
      enabled = userState.mfa.enabled;
      methods = ['totp', 'recovery'];
      hasPassword = userState.authProvider === 'local';
    } finally {
      loading = false;
    }
  });

  function confirmed(tokens: SessionTokens) {
    setTokens(tokens.access_token, tokens.refresh_token);
    // The session may now count as confirmed with a second factor
    void fetchCurrentUser();
    onconfirmed();
  }

  async function confirmPassword(e: Event) {
    e.preventDefault();
    if (!password) return;
    busy = true;
    error = '';
    try {
      confirmed(await verifyFactor(sessionTransport, { method: 'password', password }));
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }

  function signOut() {
    oncancel();
    disconnectWS();
    resetUserState();
    // On an AI agent's consent page, signing in again continues there
    window.location.hash = signInLocation();
    window.location.reload();
  }
</script>

{#if loading}
  <div class="flex items-center justify-center gap-2 py-8 text-[13px] text-muted">
    <Spinner size={16} /> Checking your sign-in options…
  </div>
{:else if enabled}
  <VerifyFactor send={sessionTransport} {methods} onverified={confirmed} submitLabel="Confirm" {oncancel} />
{:else if hasPassword}
  <form bind:this={passwordForm} onsubmit={confirmPassword} class="flex flex-col gap-4">
    {#if error}<Alert tone="danger">{error}</Alert>{/if}
    <Field label="Password" type="password" bind:value={password} required autocomplete="current-password" />
    <div class="flex gap-2">
      <Button variant="ghost" size="lg" disabled={busy} onclick={oncancel}>Cancel</Button>
      <Button type="submit" size="lg" class="flex-1" loading={busy} disabled={!password}>Confirm</Button>
    </div>
  </form>
{:else}
  <div class="flex flex-col gap-4">
    <p class="text-[13px] leading-relaxed text-muted">
      Your account signs in with {userState.authProvider === 'local' ? 'single sign-on' : titleCase(userState.authProvider)}, so there's no password to confirm.
      Sign out and sign in again, then continue within 10 minutes.
    </p>
    <div class="flex gap-2">
      <Button variant="ghost" size="lg" onclick={oncancel}>Cancel</Button>
      <Button size="lg" class="flex-1" icon="log-out" onclick={signOut}>Sign out</Button>
    </div>
  </div>
{/if}
