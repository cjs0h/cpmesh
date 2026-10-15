<script lang="ts">
  import { onMount } from 'svelte';
  import { ApiError, apiWithToken } from '../lib/api';
  import { parseAppSignIn, ssoLoginUrl } from '../lib/auth';
  import { challengeFromBody, completeSignIn, errorMessage, secondStepHeading, type MfaChallenge, type SessionTokens } from '../lib/mfa';
  import { loadPublicSettings, publicSettings } from '../lib/stores/settings.svelte';
  import Icon from '../components/Icon.svelte';
  import Logo from '../components/Logo.svelte';
  import AnnouncementBanner from '../components/layout/AnnouncementBanner.svelte';
  import AppHandoff from '../components/mfa/AppHandoff.svelte';
  import SecondFactor from '../components/mfa/SecondFactor.svelte';
  import Badge from '../components/ui/Badge.svelte';
  import Button from '../components/ui/Button.svelte';
  import Field from '../components/ui/Field.svelte';
  import Alert from '../components/ui/Alert.svelte';

  let mode: 'login' | 'register' = $state('login');
  let error = $state('');
  let success = $state('');
  let loading = $state(false);

  // The desktop app's "Sign in with browser": the finished sign-in goes to the app
  const appSignIn = parseAppSignIn(window.location.hash.split('?')[1]);
  /** Second step of the sign-in (two-factor authentication). */
  let challenge = $state<MfaChallenge | null>(null);
  /** Set once the sign-in was handed to the app. */
  let appUrl = $state('');

  // Social login status
  let socialEnabled = $state(false);
  let socialProvider = $state('');

  // Login fields
  let loginIdentifier = $state('');
  let loginPassword = $state('');

  // Register fields
  let regUsername = $state('');
  let regEmail = $state('');
  let regFullName = $state('');
  let regCountry = $state('');
  let regMobile = $state('');
  let regPassword = $state('');
  let regPasswordConfirm = $state('');
  let regErrors: Record<string, string> = $state({});

  // Resend verification
  let resendOpen = $state(false);
  let resendLoading = $state(false);
  let resendEmail = $state('');

  onMount(() => {
    // Verification links and SSO errors land here with a status in the URL
    const hash = window.location.hash;
    if (hash.includes('verified=true')) {
      success = 'Email verified — you can sign in now.';
      mode = 'login';
      window.location.hash = '#/login';
    } else if (hash.includes('verified=error')) {
      error = 'Email verification failed. The link may have expired — request a new one below.';
      mode = 'login';
      resendOpen = true;
      window.location.hash = '#/login';
    }
    const socialError = new URLSearchParams(hash.split('?')[1] || '').get('social_error');
    if (socialError) {
      error = socialError.replace(/\+/g, ' ');
      window.location.hash = '#/login';
    }

    fetch('/api/auth/social/status')
      .then((r) => r.json())
      .then((data) => {
        socialEnabled = Boolean(data.enabled);
        socialProvider = data.provider || '';
      })
      .catch(() => {});
    loadPublicSettings();
  });

  function switchMode(next: 'login' | 'register') {
    mode = next;
    error = '';
    success = '';
    regErrors = {};
  }

  function validateRegForm(): boolean {
    const errs: Record<string, string> = {};
    if (regFullName.trim().length < 2) errs.fullName = 'At least 2 characters';
    if (regFullName.trim().length > 100) errs.fullName = 'At most 100 characters';
    if (!regEmail.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) errs.email = 'Enter a valid email address';
    if (regUsername.trim().length < 3) errs.username = 'At least 3 characters';
    if (regUsername.trim().length > 50) errs.username = 'At most 50 characters';
    if (regPassword.length < 8) errs.password = 'At least 8 characters';
    if (regPassword.length > 128) errs.password = 'At most 128 characters';
    if (regPassword !== regPasswordConfirm) errs.passwordConfirm = 'Passwords do not match';
    if (regMobile && (regMobile.trim().length < 7 || regMobile.trim().length > 20)) errs.mobile = 'Between 7 and 20 characters';
    regErrors = errs;
    return Object.keys(errs).length === 0;
  }

  const strength = $derived.by(() => {
    const p = regPassword;
    if (!p) return { score: 0, label: '', tone: '' };
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

  async function handleLogin(e: Event) {
    e.preventDefault();
    error = '';
    success = '';
    loading = true;
    try {
      const tokens = await apiWithToken<SessionTokens>('/api/auth/login', null, {
        method: 'POST',
        body: JSON.stringify({ username: loginIdentifier.trim(), password: loginPassword }),
      });
      await finishSignIn(tokens);
    } catch (err) {
      const next = err instanceof ApiError ? challengeFromBody(err.data) : null;
      if (next) {
        challenge = next;
        loginPassword = '';
      } else if (err instanceof ApiError && err.message === 'email_not_verified') {
        error = err.data.message || 'Please verify your email address first.';
        resendOpen = true;
        resendEmail = loginIdentifier.includes('@') ? loginIdentifier.trim() : resendEmail;
      } else {
        error = errorMessage(err, 'Sign-in failed. Try again.');
      }
    } finally {
      loading = false;
    }
  }

  /** Stores the session and opens the dashboard, or hands the sign-in to the desktop app. */
  async function finishSignIn(tokens: SessionTokens) {
    try {
      const url = await completeSignIn(tokens, appSignIn);
      if (url) {
        appUrl = url;
        challenge = null;
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

  async function handleRegister(e: Event) {
    e.preventDefault();
    error = '';
    success = '';
    if (!validateRegForm()) return;
    loading = true;
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: regUsername.trim(),
          email: regEmail.trim(),
          full_name: regFullName.trim(),
          country: regCountry.trim() || undefined,
          mobile: regMobile.trim() || undefined,
          password: regPassword,
          password_confirm: regPasswordConfirm,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Registration failed');
      success = data.message || 'Account created! Check your inbox to verify your email.';
      resendEmail = regEmail.trim();
      mode = 'login';
    } catch (err: any) {
      error = err.message;
    } finally {
      loading = false;
    }
  }

  async function handleResend(e: Event) {
    e.preventDefault();
    if (!resendEmail) return;
    resendLoading = true;
    try {
      const res = await fetch('/api/auth/resend-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: resendEmail.trim() }),
      });
      const data = await res.json();
      success = data.message || 'Verification email sent.';
      error = '';
    } catch {
      // intentionally silent — the API answers the same way for unknown emails
    } finally {
      resendLoading = false;
    }
  }

</script>

<svelte:head>
  <title>{appUrl ? 'Signed in' : challenge ? 'Two-factor authentication' : mode === 'login' ? 'Sign in' : 'Create account'} — cpmesh</title>
</svelte:head>

<div class="flex min-h-dvh flex-col bg-bg-deep">
  <AnnouncementBanner />
  <header class="flex h-14 items-center justify-between px-5 sm:px-8">
    <a href="#/" class="inline-flex items-center gap-2" aria-label="cpmesh home">
      <Logo size={24} withText textClass="text-[15px]" />
    </a>
    <a href="#/" class="inline-flex items-center gap-1.5 text-[13px] text-muted transition-colors hover:text-fg">
      <Icon name="arrow-left" size={14} /> Back to site
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
          <h1 class="text-2xl font-semibold tracking-[-0.02em] text-fg">{mode === 'login' ? 'Sign in to cpmesh' : 'Create your account'}</h1>
          <p class="mt-1.5 text-sm text-muted">{mode === 'login' ? 'Your clipboard, on every device you own.' : 'Free, open source, end-to-end encrypted.'}</p>
        {/if}
      </div>

      <div class="rounded-lg border border-border bg-surface p-6 shadow-sm sm:p-7">
        {#if appUrl}
          <AppHandoff url={appUrl} />
        {:else if challenge}
          <SecondFactor {challenge} oncomplete={finishSignIn} oncancel={() => (challenge = null)} />
        {:else}
          <div class="mb-6 flex border-b border-border" role="tablist" aria-label="Authentication mode">
            <button type="button" role="tab" aria-selected={mode === 'login'} class="-mb-px flex-1 border-b-2 pb-2.5 text-sm font-medium transition-colors {mode === 'login' ? 'border-ink text-fg' : 'border-transparent text-muted hover:text-fg'}" onclick={() => switchMode('login')}>Sign in</button>
            <button type="button" role="tab" aria-selected={mode === 'register'} class="-mb-px flex-1 border-b-2 pb-2.5 text-sm font-medium transition-colors {mode === 'register' ? 'border-ink text-fg' : 'border-transparent text-muted hover:text-fg'}" onclick={() => switchMode('register')}>Create account</button>
          </div>

          <div class="flex flex-col gap-3">
            {#if error}<Alert tone="danger" dismissible ondismiss={() => (error = '')}>{error}</Alert>{/if}
            {#if success}<Alert tone="success" dismissible ondismiss={() => (success = '')}>{success}</Alert>{/if}
          </div>

          {#if mode === 'login'}
            <form onsubmit={handleLogin} class="mt-4 flex flex-col gap-4">
              <Field label="Username or email" bind:value={loginIdentifier} required autocomplete="username" placeholder="you@example.com" />
              <Field label="Password" type="password" bind:value={loginPassword} required minlength={8} autocomplete="current-password" placeholder="••••••••" />
              <Button type="submit" size="lg" {loading} class="mt-1 w-full">Sign in</Button>
            </form>
          {:else if !publicSettings.registrationOpen}
            <div class="mt-4">
              <Alert tone="info">Sign-up is closed on this server. Ask its administrator for an account.</Alert>
            </div>
          {:else}
            <form onsubmit={handleRegister} class="mt-4 flex flex-col gap-4" novalidate>
              <Field label="Full name" bind:value={regFullName} required autocomplete="name" error={regErrors.fullName} />
              <Field label="Email" type="email" bind:value={regEmail} required autocomplete="email" error={regErrors.email} />
              <Field label="Username" bind:value={regUsername} required autocomplete="username" error={regErrors.username} hint="3–50 characters, shown to your other devices" />
              <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <Field label="Country" bind:value={regCountry} optional autocomplete="country-name" />
                <Field label="Mobile" type="tel" bind:value={regMobile} optional autocomplete="tel" error={regErrors.mobile} />
              </div>
              <div class="flex flex-col gap-2">
                <Field label="Password" type="password" bind:value={regPassword} required minlength={8} maxlength={128} autocomplete="new-password" error={regErrors.password} />
                {#if regPassword}
                  <div class="flex items-center gap-3 px-0.5">
                    <div class="flex flex-1 gap-1" aria-hidden="true">
                      {#each Array(5) as _, i (i)}
                        <span class="h-1 flex-1 rounded-full transition-colors duration-200 {i < strength.score ? strength.tone : 'bg-surface-3'}"></span>
                      {/each}
                    </div>
                    <span class="w-16 text-right text-xs text-muted">{strength.label}</span>
                  </div>
                {/if}
              </div>
              <Field label="Confirm password" type="password" bind:value={regPasswordConfirm} required autocomplete="new-password" error={regErrors.passwordConfirm} />
              <Button type="submit" size="lg" {loading} class="mt-1 w-full">Create account</Button>
              <p class="text-center text-xs leading-relaxed text-dim">We only use your email to verify the account and for security notices.</p>
            </form>
          {/if}

          {#if socialEnabled}
            <div class="my-5 flex items-center gap-3">
              <div class="h-px flex-1 bg-border"></div>
              <span class="text-xs text-dim">or</span>
              <div class="h-px flex-1 bg-border"></div>
            </div>
            <Button href={ssoLoginUrl(appSignIn)} variant="secondary" size="lg" icon="globe" class="w-full">
              Continue with {socialProvider ? socialProvider.charAt(0).toUpperCase() + socialProvider.slice(1) : 'SSO'}
            </Button>
          {/if}

          {#if mode === 'login'}
            <div class="mt-6 border-t border-border pt-4">
              <button type="button" class="flex w-full items-center justify-between text-[13px] text-muted transition-colors hover:text-fg" aria-expanded={resendOpen} onclick={() => (resendOpen = !resendOpen)}>
                Didn't receive the verification email?
                <Icon name="chevron-down" size={14} class="transition-transform duration-200 {resendOpen ? 'rotate-180' : ''}" />
              </button>
              {#if resendOpen}
                <form onsubmit={handleResend} class="mt-3 flex gap-2">
                  <Field type="email" bind:value={resendEmail} placeholder="Your email address" class="flex-1" required />
                  <Button type="submit" variant="secondary" loading={resendLoading} disabled={!resendEmail}>Resend</Button>
                </form>
              {/if}
            </div>
          {/if}
        {/if}
      </div>

      <p class="mt-6 text-center text-xs text-dim">
        End-to-end encrypted · Open source · <a href="https://github.com/cjs0h/cpmesh" target="_blank" rel="noopener" class="underline underline-offset-4 hover:text-fg">Self-host it</a>
      </p>
    </div>
  </main>
</div>
