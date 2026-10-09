<script lang="ts">
  import { setTokens } from '../lib/auth';
  import Icon from '../components/Icon.svelte';
  import Logo from '../components/Logo.svelte';
  import SyncDemo from '../components/landing/SyncDemo.svelte';
  import Button from '../components/ui/Button.svelte';
  import Field from '../components/ui/Field.svelte';
  import Alert from '../components/ui/Alert.svelte';
  import RetroGrid from '../components/magic/RetroGrid.svelte';

  let mode: 'login' | 'register' = $state('login');
  let error = $state('');
  let success = $state('');
  let loading = $state(false);

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

  // Check URL params for verification status and social errors
  $effect(() => {
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
      error = decodeURIComponent(socialError.replace(/\+/g, ' '));
      window.location.hash = '#/login';
    }
  });

  // Fetch social login status
  $effect(() => {
    fetch('/api/auth/social/status')
      .then((r) => r.json())
      .then((data) => {
        socialEnabled = Boolean(data.enabled);
        socialProvider = data.provider || '';
      })
      .catch(() => {});
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
    const tones = ['bg-rose', 'bg-rose', 'bg-yellow', 'bg-cyan', 'bg-mint', 'bg-mint'];
    return { score, label: labels[score], tone: tones[score] };
  });

  async function handleLogin(e: Event) {
    e.preventDefault();
    error = '';
    success = '';
    loading = true;
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: loginIdentifier.trim(), password: loginPassword }),
      });
      const data = await res.json();
      if (!res.ok) {
        if (data.error === 'email_not_verified') {
          error = data.message || 'Please verify your email address first.';
          resendOpen = true;
          resendEmail = loginIdentifier.includes('@') ? loginIdentifier.trim() : resendEmail;
          return;
        }
        throw new Error(data.error || 'Login failed');
      }
      setTokens(data.access_token, data.refresh_token);
      window.location.hash = '#/';
      window.location.reload();
    } catch (err: any) {
      error = err.message;
    } finally {
      loading = false;
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

  const bullets = [
    { icon: 'lock', title: 'Encrypted before it leaves', desc: 'AES-256-GCM on-device. The relay only ever stores ciphertext.' },
    { icon: 'zap', title: 'Sub-second delivery', desc: 'WebSocket push to every paired device the instant you copy.' },
    { icon: 'shield-check', title: 'Open source, self-hostable', desc: 'MIT / Apache-2.0. Run your own relay with one Docker command.' },
  ];
</script>

<svelte:head>
  <title>{mode === 'login' ? 'Sign in' : 'Create account'} — cpmesh</title>
</svelte:head>

<div class="relative grid min-h-dvh grid-cols-1 bg-bg lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
  <!-- Brand panel -->
  <aside class="grid-paper relative hidden overflow-hidden border-r-2 border-ink bg-bg-deep lg:flex lg:flex-col lg:justify-between lg:p-12 2xl:p-16">
    <RetroGrid class="top-auto! h-[45%]" opacity={0.5} fadeTo="var(--color-bg-deep)" />

    <a href="#/" class="relative inline-flex w-fit items-center gap-2.5">
      <Logo size={38} withText textClass="text-lg" />
    </a>

    <div class="relative my-10 max-w-2xl">
      <h1 class="font-head text-[clamp(2rem,3.2vw,3.4rem)] leading-[1.05] text-ink">
        Copy on one device.<br />
        <span class="text-gradient">Paste on all of them.</span>
      </h1>
      <p class="mt-4 max-w-md text-[15px] leading-relaxed text-muted">Your clipboard, synced across every machine you own — sealed with keys that never leave your hardware.</p>

      <div class="mt-8 max-w-[460px]">
        <SyncDemo compact />
      </div>

      <ul class="mt-9 grid gap-3">
        {#each bullets as b, i (b.title)}
          <li class="panel flex items-start gap-3 px-4 py-3" style="--panel-shadow: {['var(--color-accent)', 'var(--color-cyan)', 'var(--color-mint)'][i]};">
            <span class="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded border-2 border-ink text-ink {['bg-accent', 'bg-cyan', 'bg-mint'][i]}"><Icon name={b.icon} size={15} strokeWidth={2.5} /></span>
            <div>
              <p class="font-head text-[13px] text-ink">{b.title}</p>
              <p class="text-[13px] text-muted">{b.desc}</p>
            </div>
          </li>
        {/each}
      </ul>
    </div>

    <p class="relative font-head text-[11px] uppercase tracking-[0.12em] text-dim">© {new Date().getFullYear()} cpmesh · MIT / Apache-2.0</p>
  </aside>

  <!-- Form panel -->
  <main class="dot-grid relative flex items-center justify-center px-5 py-10 sm:px-8">
    <div class="relative w-full max-w-[440px] animate-[fade-up_0.5s_var(--ease-out-expo)]">
      <div class="mb-8 flex flex-col items-center text-center lg:hidden">
        <a href="#/" class="inline-flex"><Logo size={48} /></a>
        <h1 class="mt-5 font-head text-2xl text-ink">Welcome to cpmesh</h1>
        <p class="mt-1 text-sm text-muted">Encrypted clipboard sync for every device</p>
      </div>

      <div class="panel panel-lg rounded-lg p-6 sm:p-8" style="--panel-shadow: var(--color-yellow);">
        <!-- Segmented control -->
        <div class="mb-6 grid grid-cols-2 gap-1 rounded-md border-2 border-ink bg-surface-2 p-1 shadow-xs" role="tablist" aria-label="Authentication mode">
          <button type="button" role="tab" aria-selected={mode === 'login'} class="h-10 whitespace-nowrap rounded border-2 px-1 font-head text-[10.5px] uppercase tracking-[0.03em] transition-[background-color,box-shadow,transform] sm:text-[12px] sm:tracking-[0.06em] {mode === 'login' ? 'border-ink bg-yellow text-ink shadow-sm' : 'border-transparent text-muted hover:text-ink'}" onclick={() => switchMode('login')}>Sign in</button>
          <button type="button" role="tab" aria-selected={mode === 'register'} class="h-10 whitespace-nowrap rounded border-2 px-1 font-head text-[10.5px] uppercase tracking-[0.03em] transition-[background-color,box-shadow,transform] sm:text-[12px] sm:tracking-[0.06em] {mode === 'register' ? 'border-ink bg-yellow text-ink shadow-sm' : 'border-transparent text-muted hover:text-ink'}" onclick={() => switchMode('register')}>Create account</button>
        </div>

        <div class="flex flex-col gap-3">
          {#if error}<Alert tone="danger" dismissible ondismiss={() => (error = '')}>{error}</Alert>{/if}
          {#if success}<Alert tone="success" dismissible ondismiss={() => (success = '')}>{success}</Alert>{/if}
        </div>

        {#if mode === 'login'}
          <form onsubmit={handleLogin} class="mt-4 flex flex-col gap-4">
            <Field label="Username or email" icon="user" bind:value={loginIdentifier} required autocomplete="username" placeholder="you@example.com" />
            <Field label="Password" type="password" icon="lock" bind:value={loginPassword} required minlength={8} autocomplete="current-password" placeholder="••••••••" />
            <Button type="submit" size="lg" {loading} shine class="mt-1 w-full">Sign in</Button>
          </form>
        {:else}
          <form onsubmit={handleRegister} class="mt-4 flex flex-col gap-4" novalidate>
            <Field label="Full name" icon="user" bind:value={regFullName} required autocomplete="name" error={regErrors.fullName} />
            <Field label="Email" type="email" icon="at-sign" bind:value={regEmail} required autocomplete="email" error={regErrors.email} />
            <Field label="Username" icon="hash" bind:value={regUsername} required autocomplete="username" error={regErrors.username} hint="3–50 characters, shown to your other devices" />
            <div class="grid grid-cols-2 gap-3">
              <Field label="Country" icon="map-pin" bind:value={regCountry} optional autocomplete="country-name" />
              <Field label="Mobile" type="tel" icon="phone" bind:value={regMobile} optional autocomplete="tel" error={regErrors.mobile} />
            </div>
            <div class="flex flex-col gap-2">
              <Field label="Password" type="password" icon="lock" bind:value={regPassword} required minlength={8} maxlength={128} autocomplete="new-password" error={regErrors.password} />
              {#if regPassword}
                <div class="flex items-center gap-3 px-0.5">
                  <div class="flex flex-1 gap-1" aria-hidden="true">
                    {#each Array(5) as _, i (i)}
                      <span class="h-2 flex-1 rounded-sm border-2 border-ink transition-colors duration-300 {i < strength.score ? strength.tone : 'bg-surface-2'}"></span>
                    {/each}
                  </div>
                  <span class="w-16 text-right font-head text-[10.5px] uppercase tracking-wide text-muted">{strength.label}</span>
                </div>
              {/if}
            </div>
            <Field label="Confirm password" type="password" icon="check" bind:value={regPasswordConfirm} required autocomplete="new-password" error={regErrors.passwordConfirm} />
            <Button type="submit" size="lg" {loading} shine class="mt-1 w-full">Create account</Button>
            <p class="text-center text-[11.5px] leading-relaxed text-dim">We only use your email to verify the account and for security notices.</p>
          </form>
        {/if}

        {#if socialEnabled}
          <div class="my-5 flex items-center gap-3">
            <div class="h-0.5 flex-1 bg-ink/15"></div>
            <span class="font-head text-[10px] uppercase tracking-[0.16em] text-dim">or</span>
            <div class="h-0.5 flex-1 bg-ink/15"></div>
          </div>
          <Button href="/api/auth/social/login" variant="secondary" size="lg" icon="globe" class="w-full">
            Continue with {socialProvider ? socialProvider.charAt(0).toUpperCase() + socialProvider.slice(1) : 'SSO'}
          </Button>
        {/if}

        {#if mode === 'login'}
          <div class="mt-6 border-t-2 border-ink/15 pt-4">
            <button type="button" class="flex w-full items-center justify-between text-[12.5px] font-semibold text-muted transition-colors hover:text-ink" aria-expanded={resendOpen} onclick={() => (resendOpen = !resendOpen)}>
              Didn't receive the verification email?
              <Icon name="chevron-down" size={14} strokeWidth={2.5} class="transition-transform duration-300 {resendOpen ? 'rotate-180' : ''}" />
            </button>
            {#if resendOpen}
              <form onsubmit={handleResend} class="mt-3 flex gap-2 animate-[fade-up_0.3s_var(--ease-out-expo)]">
                <Field type="email" icon="mail" bind:value={resendEmail} placeholder="Your email address" class="flex-1" required />
                <Button type="submit" variant="outline" loading={resendLoading} disabled={!resendEmail}>Resend</Button>
              </form>
            {/if}
          </div>
        {/if}
      </div>

      <p class="mt-7 text-center">
        <a href="#/" class="inline-flex items-center gap-1.5 font-head text-[11px] uppercase tracking-[0.1em] text-muted underline decoration-2 decoration-yellow underline-offset-4 transition-colors hover:text-ink">
          <Icon name="arrow-left" size={14} strokeWidth={2.5} /> Back to cpmesh.com
        </a>
      </p>
    </div>
  </main>
</div>
