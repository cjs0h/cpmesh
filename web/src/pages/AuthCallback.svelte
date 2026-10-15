<script lang="ts">
  import { onMount } from 'svelte';
  import { loginPageUrl, parseAppSignIn, setTokens } from '../lib/auth';
  import {
    challengeFromStatus,
    completeSignIn,
    errorMessage,
    getMfaStatus,
    secondStepHeading,
    ticketTransport,
    type MfaChallenge,
    type SessionTokens,
  } from '../lib/mfa';
  import Logo from '../components/Logo.svelte';
  import AppHandoff from '../components/mfa/AppHandoff.svelte';
  import SecondFactor from '../components/mfa/SecondFactor.svelte';
  import Alert from '../components/ui/Alert.svelte';
  import Badge from '../components/ui/Badge.svelte';
  import Button from '../components/ui/Button.svelte';

  const params = new URLSearchParams(window.location.hash.split('?')[1] || '');
  // Single sign-on started by the desktop app: the finished sign-in goes to the app
  const appSignIn = parseAppSignIn(params.toString());

  /** Second step, when the account needs two-factor authentication. */
  let challenge = $state<MfaChallenge | null>(null);
  let error = $state('');
  /** Set once the sign-in was handed to the app. */
  let appUrl = $state('');

  onMount(async () => {
    const accessToken = params.get('access_token');
    const refreshToken = params.get('refresh_token');
    const ticket = params.get('mfa_token');

    if (accessToken && refreshToken) {
      setTokens(accessToken, refreshToken);
      window.location.hash = '#/';
      window.location.reload();
      return;
    }
    if (!ticket) {
      // No tokens, redirect to login
      window.location.hash = '#/login';
      return;
    }

    // Keep the single-use ticket out of the address bar and the history
    history.replaceState(history.state, '', '#/auth/callback');
    try {
      challenge = challengeFromStatus(ticket, await getMfaStatus(ticketTransport(() => ticket)));
    } catch (err) {
      error = errorMessage(err);
    }
  });

  async function finish(tokens: SessionTokens) {
    try {
      const url = await completeSignIn(tokens, appSignIn);
      if (url) {
        appUrl = url;
        window.location.href = url;
        return;
      }
      window.location.hash = '#/';
      window.location.reload();
    } catch (err) {
      challenge = null;
      error = `The cpmesh app couldn't take over the sign-in (${errorMessage(err)}). Sign in again to retry.`;
    }
  }

  function startOver() {
    window.location.hash = loginPageUrl(appSignIn);
  }
</script>

<svelte:head>
  <title>{challenge ? 'Two-factor authentication' : 'Signing in'} — cpmesh</title>
</svelte:head>

{#if !challenge && !error && !appUrl}
  <div class="flex h-dvh flex-col items-center justify-center gap-5 bg-bg">
    <Logo size={40} />
    <div class="flex items-center gap-2 text-[13px] text-muted">
      <span class="inline-block h-4 w-4 rounded-full border-2 border-border-strong border-t-ink animate-[spin_0.7s_linear_infinite]"></span>
      Completing sign in…
    </div>
  </div>
{:else}
  <div class="flex min-h-dvh flex-col bg-bg-deep">
    <header class="flex h-14 items-center px-5 sm:px-8">
      <a href="#/" class="inline-flex items-center gap-2" aria-label="cpmesh home">
        <Logo size={24} withText textClass="text-[15px]" />
      </a>
    </header>

    <main class="flex flex-1 items-center justify-center px-5 pb-16 pt-6 sm:px-8">
      <div class="w-full max-w-[400px]">
        {#if appSignIn && !appUrl}
          <div class="mb-4 flex justify-center">
            <Badge size="md" icon="monitor">Signing in to the cpmesh app</Badge>
          </div>
        {/if}
        <div class="mb-6 text-center">
          {#if appUrl}
            <h1 class="text-2xl font-semibold tracking-[-0.02em] text-fg">You're signed in</h1>
          {:else if challenge}
            {@const heading = secondStepHeading(challenge.stage)}
            <h1 class="text-2xl font-semibold tracking-[-0.02em] text-fg">{heading.title}</h1>
            <p class="mt-1.5 text-sm text-muted">{heading.subtitle}</p>
          {:else}
            <h1 class="text-2xl font-semibold tracking-[-0.02em] text-fg">Sign-in didn't finish</h1>
          {/if}
        </div>

        <div class="rounded-lg border border-border bg-surface p-6 shadow-sm sm:p-7">
          {#if appUrl}
            <AppHandoff url={appUrl} />
          {:else if challenge}
            <SecondFactor {challenge} oncomplete={finish} oncancel={startOver} />
          {:else}
            <div class="flex flex-col gap-4">
              <Alert tone="danger">{error}</Alert>
              <Button size="lg" class="w-full" onclick={startOver}>Back to sign in</Button>
            </div>
          {/if}
        </div>
      </div>
    </main>
  </div>
{/if}
