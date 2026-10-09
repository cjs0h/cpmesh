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

<div class="dot-grid flex h-dvh flex-col items-center justify-center gap-5 bg-bg">
  <div class="animate-[float-y_3s_ease-in-out_infinite]"><Logo size={48} /></div>
  <div class="flex items-center gap-2 font-head text-[12px] uppercase tracking-[0.1em] text-muted">
    <span class="inline-block h-4 w-4 rounded-full border-[3px] border-ink/20 border-t-ink animate-[spin_0.7s_linear_infinite]"></span>
    Completing sign in…
  </div>
</div>
