<script lang="ts">
  import { setTokens } from '../lib/auth';
  import Icon from '../components/Icon.svelte';

  let mode: 'login' | 'register' = $state('login');
  let error = $state('');
  let success = $state('');
  let loading = $state(false);

  // Social login status
  let socialEnabled = $state(false);
  let socialProvider = $state('');

  // Login fields
  let loginIdentifier = $state(''); // username or email
  let loginPassword = $state('');

  // Register fields
  let regUsername = $state('');
  let regEmail = $state('');
  let regFullName = $state('');
  let regCountry = $state('');
  let regMobile = $state('');
  let regPassword = $state('');
  let regPasswordConfirm = $state('');

  // Field validation state
  let regErrors: Record<string, string> = $state({});

  // Check URL params for verification status and social errors
  $effect(() => {
    const hash = window.location.hash;
    if (hash.includes('verified=true')) {
      success = 'Email verified successfully! You can now log in.';
      mode = 'login';
      window.location.hash = '#/login';
    } else if (hash.includes('verified=error')) {
      error = 'Email verification failed. The link may have expired. Please request a new one.';
      mode = 'login';
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
      .then(r => r.json())
      .then(data => {
        socialEnabled = data.enabled;
        socialProvider = data.provider || '';
      })
      .catch(() => {});
  });

  function validateRegForm(): boolean {
    regErrors = {};
    if (regFullName.trim().length < 2) regErrors.fullName = 'At least 2 characters';
    if (regFullName.trim().length > 100) regErrors.fullName = 'At most 100 characters';
    if (!regEmail.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) regErrors.email = 'Invalid email format';
    if (regUsername.trim().length < 3) regErrors.username = 'At least 3 characters';
    if (regUsername.trim().length > 50) regErrors.username = 'At most 50 characters';
    if (regPassword.length < 8) regErrors.password = 'At least 8 characters';
    if (regPassword.length > 128) regErrors.password = 'At most 128 characters';
    if (regPassword !== regPasswordConfirm) regErrors.passwordConfirm = 'Passwords do not match';
    if (regMobile && (regMobile.trim().length < 7 || regMobile.trim().length > 20)) {
      regErrors.mobile = 'Between 7 and 20 characters';
    }
    return Object.keys(regErrors).length === 0;
  }

  // Password strength indicator
  let passwordStrength = $derived.by(() => {
    const p = regPassword;
    if (!p) return { label: '', color: '', width: '0%' };
    let score = 0;
    if (p.length >= 8) score++;
    if (p.length >= 12) score++;
    if (/[A-Z]/.test(p) && /[a-z]/.test(p)) score++;
    if (/\d/.test(p)) score++;
    if (/[^A-Za-z0-9]/.test(p)) score++;
    if (score <= 1) return { label: 'Weak', color: '#ef4444', width: '20%' };
    if (score <= 2) return { label: 'Fair', color: '#f59e0b', width: '40%' };
    if (score <= 3) return { label: 'Good', color: '#3b82f6', width: '60%' };
    if (score <= 4) return { label: 'Strong', color: '#22c55e', width: '80%' };
    return { label: 'Very Strong', color: '#16a34a', width: '100%' };
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
        body: JSON.stringify({ username: loginIdentifier, password: loginPassword }),
      });
      const data = await res.json();
      if (!res.ok) {
        if (data.error === 'email_not_verified') {
          error = data.message || 'Please verify your email address first.';
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
      success = data.message || 'Account created! Please check your email to verify your account.';
      mode = 'login';
    } catch (err: any) {
      error = err.message;
    } finally {
      loading = false;
    }
  }

  let resendLoading = $state(false);
  let resendEmail = $state('');

  async function handleResend() {
    if (!resendEmail) return;
    resendLoading = true;
    try {
      const res = await fetch('/api/auth/resend-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: resendEmail }),
      });
      const data = await res.json();
      success = data.message || 'Verification email sent.';
      error = '';
    } catch {
      // intentionally silent
    } finally {
      resendLoading = false;
    }
  }
</script>

<div class="flex items-center justify-center min-h-screen bg-bg relative overflow-hidden py-8">
  <div class="absolute w-[500px] h-[500px] rounded-full top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none" style="background: radial-gradient(circle, rgba(129, 140, 248, 0.08) 0%, transparent 70%)"></div>
  <div class="relative w-[440px] bg-bg-card border border-border rounded-xl px-8 py-10 shadow-lg">
    <div
      class="w-11 h-11 rounded-lg flex items-center justify-center text-white mx-auto mb-4 shadow-primary"
      style="background: linear-gradient(135deg, var(--color-primary) 0%, var(--color-primary-dim) 100%)"
    >
      <Icon name="network" size={22} />
    </div>
    <h1 class="text-[26px] font-bold text-center tracking-[-0.03em]">cpmesh</h1>
    <p class="text-center text-muted text-[13.5px] mb-7">Encrypted clipboard sync</p>

    <div class="flex gap-1 mb-6 bg-bg-input rounded p-1 border border-border">
      <button
        class="flex-1 py-[9px] border-none rounded-sm text-[13.5px] font-medium transition-all duration-150 {mode === 'login' ? 'bg-primary text-white shadow-[0_2px_8px_rgba(129,140,248,0.3)]' : 'bg-transparent text-muted'}"
        onclick={() => { mode = 'login'; error = ''; success = ''; }}
      >Login</button>
      <button
        class="flex-1 py-[9px] border-none rounded-sm text-[13.5px] font-medium transition-all duration-150 {mode === 'register' ? 'bg-primary text-white shadow-[0_2px_8px_rgba(129,140,248,0.3)]' : 'bg-transparent text-muted'}"
        onclick={() => { mode = 'register'; error = ''; success = ''; }}
      >Register</button>
    </div>

    {#if error}
      <div class="bg-danger-glow border border-danger/30 text-danger px-3.5 py-2.5 rounded text-[13px] mb-4">{error}</div>
    {/if}
    {#if success}
      <div class="bg-[rgba(34,197,94,0.08)] border border-[rgba(34,197,94,0.3)] text-[#22c55e] px-3.5 py-2.5 rounded text-[13px] mb-4">{success}</div>
    {/if}

    {#if mode === 'login'}
      <form onsubmit={handleLogin}>
        <label class="flex flex-col gap-1.5 mb-4">
          <span class="text-[13px] text-muted font-medium">Username or Email</span>
          <input type="text" bind:value={loginIdentifier} required autocomplete="username"
            class="py-[11px] px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
        </label>
        <label class="flex flex-col gap-1.5 mb-4">
          <span class="text-[13px] text-muted font-medium">Password</span>
          <input type="password" bind:value={loginPassword} required minlength="8" autocomplete="current-password"
            class="py-[11px] px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
        </label>
        <button type="submit" class="w-full py-3 border-none rounded bg-primary text-white text-sm font-semibold transition-all duration-200 flex items-center justify-center gap-2 hover:not-disabled:bg-primary-hover hover:not-disabled:shadow-primary disabled:opacity-60" disabled={loading}>
          {#if loading}
            <span class="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-[spin_0.6s_linear_infinite]"></span>
          {:else}
            Login
          {/if}
        </button>
      </form>

      {#if socialEnabled}
        <div class="flex items-center gap-3 my-4">
          <div class="flex-1 h-px bg-border"></div>
          <span class="text-[12px] text-muted uppercase tracking-wider">or</span>
          <div class="flex-1 h-px bg-border"></div>
        </div>
        <a href="/api/auth/social/login" class="w-full py-3 border border-border rounded bg-bg-input text-text text-sm font-medium transition-all duration-200 flex items-center justify-center gap-2 hover:bg-bg-hover hover:border-border-hover no-underline">
          <Icon name="network" size={16} />
          Continue with {socialProvider || 'Social Login'}
        </a>
      {/if}

      <!-- Resend verification -->
      <div class="mt-4 pt-4 border-t border-border">
        <p class="text-[12px] text-muted mb-2">Didn't receive a verification email?</p>
        <div class="flex gap-2">
          <input type="email" bind:value={resendEmail} placeholder="Your email address"
            class="flex-1 py-2 px-3 border border-border rounded bg-bg-input text-text text-[13px] outline-none focus:border-primary" />
          <button onclick={handleResend} disabled={resendLoading || !resendEmail}
            class="px-3 py-2 border-none rounded bg-bg-input border border-border text-[13px] text-muted transition-all hover:text-text hover:border-primary disabled:opacity-50">
            Resend
          </button>
        </div>
      </div>
    {:else}
      <form onsubmit={handleRegister}>
        <label class="flex flex-col gap-1.5 mb-3">
          <span class="text-[13px] text-muted font-medium">Full Name <span class="text-danger">*</span></span>
          <input type="text" bind:value={regFullName} required minlength="2" maxlength="100" autocomplete="name"
            class="py-[11px] px-3.5 border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)] {regErrors.fullName ? 'border-danger' : 'border-border'}" />
          {#if regErrors.fullName}<span class="text-[11px] text-danger">{regErrors.fullName}</span>{/if}
        </label>

        <label class="flex flex-col gap-1.5 mb-3">
          <span class="text-[13px] text-muted font-medium">Email <span class="text-danger">*</span></span>
          <input type="email" bind:value={regEmail} required autocomplete="email"
            class="py-[11px] px-3.5 border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)] {regErrors.email ? 'border-danger' : 'border-border'}" />
          {#if regErrors.email}<span class="text-[11px] text-danger">{regErrors.email}</span>{/if}
        </label>

        <label class="flex flex-col gap-1.5 mb-3">
          <span class="text-[13px] text-muted font-medium">Username <span class="text-danger">*</span></span>
          <input type="text" bind:value={regUsername} required minlength="3" maxlength="50" autocomplete="username"
            class="py-[11px] px-3.5 border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)] {regErrors.username ? 'border-danger' : 'border-border'}" />
          {#if regErrors.username}<span class="text-[11px] text-danger">{regErrors.username}</span>{/if}
        </label>

        <div class="flex gap-3 mb-3">
          <label class="flex flex-col gap-1.5 flex-1">
            <span class="text-[13px] text-muted font-medium">Country</span>
            <input type="text" bind:value={regCountry} autocomplete="country-name" placeholder="Optional"
              class="py-[11px] px-3.5 border border-border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)]" />
          </label>
          <label class="flex flex-col gap-1.5 flex-1">
            <span class="text-[13px] text-muted font-medium">Mobile</span>
            <input type="tel" bind:value={regMobile} autocomplete="tel" placeholder="Optional"
              class="py-[11px] px-3.5 border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)] {regErrors.mobile ? 'border-danger' : 'border-border'}" />
            {#if regErrors.mobile}<span class="text-[11px] text-danger">{regErrors.mobile}</span>{/if}
          </label>
        </div>

        <label class="flex flex-col gap-1.5 mb-1">
          <span class="text-[13px] text-muted font-medium">Password <span class="text-danger">*</span></span>
          <input type="password" bind:value={regPassword} required minlength="8" maxlength="128" autocomplete="new-password"
            class="py-[11px] px-3.5 border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)] {regErrors.password ? 'border-danger' : 'border-border'}" />
          {#if regErrors.password}<span class="text-[11px] text-danger">{regErrors.password}</span>{/if}
        </label>
        {#if regPassword}
          <div class="flex items-center gap-2 mb-3">
            <div class="flex-1 h-1.5 bg-bg-input rounded-full overflow-hidden">
              <div class="h-full rounded-full transition-all duration-300" style="width: {passwordStrength.width}; background: {passwordStrength.color}"></div>
            </div>
            <span class="text-[11px] font-medium" style="color: {passwordStrength.color}">{passwordStrength.label}</span>
          </div>
        {:else}
          <div class="mb-3"></div>
        {/if}

        <label class="flex flex-col gap-1.5 mb-4">
          <span class="text-[13px] text-muted font-medium">Confirm Password <span class="text-danger">*</span></span>
          <input type="password" bind:value={regPasswordConfirm} required autocomplete="new-password"
            class="py-[11px] px-3.5 border rounded bg-bg-input text-text text-sm outline-none transition-all duration-150 focus:border-primary focus:shadow-[0_0_0_3px_var(--color-primary-glow)] {regErrors.passwordConfirm ? 'border-danger' : 'border-border'}" />
          {#if regErrors.passwordConfirm}<span class="text-[11px] text-danger">{regErrors.passwordConfirm}</span>{/if}
        </label>

        <button type="submit" class="w-full py-3 border-none rounded bg-primary text-white text-sm font-semibold transition-all duration-200 flex items-center justify-center gap-2 hover:not-disabled:bg-primary-hover hover:not-disabled:shadow-primary disabled:opacity-60" disabled={loading}>
          {#if loading}
            <span class="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-[spin_0.6s_linear_infinite]"></span>
          {:else}
            Create Account
          {/if}
        </button>
      </form>

      {#if socialEnabled}
        <div class="flex items-center gap-3 my-4">
          <div class="flex-1 h-px bg-border"></div>
          <span class="text-[12px] text-muted uppercase tracking-wider">or</span>
          <div class="flex-1 h-px bg-border"></div>
        </div>
        <a href="/api/auth/social/login" class="w-full py-3 border border-border rounded bg-bg-input text-text text-sm font-medium transition-all duration-200 flex items-center justify-center gap-2 hover:bg-bg-hover hover:border-border-hover no-underline">
          <Icon name="network" size={16} />
          Sign up with {socialProvider || 'Social Login'}
        </a>
      {/if}
    {/if}

    <div class="text-center mt-5">
      <a href="#/" class="inline-flex items-center gap-1.5 text-[13px] text-muted no-underline transition-colors duration-150 hover:text-text hover:no-underline">
        <Icon name="arrow-left" size={14} /> Back to home
      </a>
    </div>
  </div>
</div>
