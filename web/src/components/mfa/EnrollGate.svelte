<script lang="ts">
  import { setTokens, signInLocation } from '../../lib/auth';
  import { sessionTransport, type EnrollResult } from '../../lib/mfa';
  import { publicSettings } from '../../lib/stores/settings.svelte';
  import { toast } from '../../lib/stores/toast.svelte';
  import { fetchCurrentUser, resetUserState, userState } from '../../lib/stores/user.svelte';
  import { disconnectWS } from '../../lib/ws';
  import Icon from '../Icon.svelte';
  import Logo from '../Logo.svelte';
  import EnrollFactor from './EnrollFactor.svelte';
  import RecoveryCodes from './RecoveryCodes.svelte';

  // Shown instead of the app to signed-in users who must set up two-factor
  // authentication (sessions from before it was required, or after an admin reset it).

  let recoveryCodes = $state<string[] | null>(null);

  async function enrolled(result: EnrollResult) {
    setTokens(result.access_token, result.refresh_token);
    if (result.recovery_codes?.length) recoveryCodes = result.recovery_codes;
    else await finish();
  }

  async function finish() {
    await fetchCurrentUser();
    toast.success('Two-factor authentication is on', "You'll confirm it's you this way each time you sign in.");
  }

  function signOut() {
    disconnectWS();
    resetUserState();
    // On an AI agent's consent page, signing in again continues there
    window.location.hash = signInLocation();
    window.location.reload();
  }
</script>

<div class="flex min-h-dvh flex-col bg-bg-deep">
  <header class="flex h-14 items-center justify-between px-5 sm:px-8">
    <Logo size={24} withText textClass="text-[15px]" />
    <button type="button" class="inline-flex items-center gap-1.5 text-[13px] text-muted transition-colors hover:text-fg" onclick={signOut}>
      <Icon name="log-out" size={14} /> Sign out
    </button>
  </header>

  <main class="flex flex-1 items-center justify-center px-5 pb-16 pt-6 sm:px-8">
    <div class="w-full max-w-[420px]">
      <div class="mb-6 text-center">
        <h1 class="text-2xl font-semibold tracking-[-0.02em] text-fg">
          {recoveryCodes ? 'Two-factor authentication is on' : 'Set up two-factor authentication'}
        </h1>
        <p class="mt-1.5 text-sm text-muted">
          {#if recoveryCodes}
            One last step before you continue.
          {:else}
            Your account{userState.username ? ` (@${userState.username})` : ''} needs a second step at sign-in, in addition to your password or single sign-on.
          {/if}
        </p>
      </div>

      <div class="rounded-lg border border-border bg-surface p-6 shadow-sm sm:p-7">
        {#if recoveryCodes}
          <RecoveryCodes codes={recoveryCodes} account={userState.email || userState.username} onconfirm={finish} />
        {:else}
          <EnrollFactor send={sessionTransport} passkeysAvailable={publicSettings.passkeysAvailable} onenrolled={enrolled} />
        {/if}
      </div>
    </div>
  </main>
</div>
