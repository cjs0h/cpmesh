<script lang="ts">
  import { setTokens } from '../lib/auth';

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

<div class="flex items-center justify-center min-h-screen bg-bg">
  <div class="text-center">
    <span class="inline-block w-6 h-6 border-2 border-primary/30 border-t-primary rounded-full animate-[spin_0.6s_linear_infinite] mb-3"></span>
    <p class="text-muted text-sm">Completing sign in...</p>
  </div>
</div>
