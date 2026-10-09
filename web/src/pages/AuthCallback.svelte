<script lang="ts">
  import { setTokens } from '../lib/auth';
  import Logo from '../components/Logo.svelte';

  $effect(() => {
    const hash = window.location.hash;
    const params = new URLSearchParams(hash.split('?')[1] || '');
    const accessToken = params.get('access_token');
    const refreshToken = params.get('refresh_token');

    if (accessToken && refreshToken) {
      setTokens(accessToken, refreshToken);
      window.location.hash = '#/';
      window.location.reload();
    } else {
      // No tokens, redirect to login
      window.location.hash = '#/login';
    }
  });
</script>

<div class="flex h-dvh flex-col items-center justify-center gap-5 bg-bg">
  <Logo size={40} />
  <div class="flex items-center gap-2 text-[13px] text-muted">
    <span class="inline-block h-4 w-4 rounded-full border-2 border-border-strong border-t-ink animate-[spin_0.7s_linear_infinite]"></span>
    Completing sign in…
  </div>
</div>
