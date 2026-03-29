<script lang="ts">
  import { location } from 'svelte-spa-router';
  import { userState, resetUserState } from '../../lib/stores/user.svelte';
  import { disconnectWS } from '../../lib/ws';
  import Icon from '../Icon.svelte';

  function logout() {
    disconnectWS();
    resetUserState();
    window.location.hash = '#/login';
    window.location.reload();
  }

  const pageTitles: Record<string, string> = {
    '/': 'Dashboard',
    '/clipboard': 'Clipboard',
    '/devices': 'Devices',
    '/settings': 'Settings',
    '/admin/users': 'Users',
    '/admin/plans': 'Plans',
    '/admin/downloads': 'Downloads',
    '/admin/settings': 'Site Settings',
    '/admin/stats': 'Stats',
  };

  let pageTitle = $derived(pageTitles[$location] || 'Dashboard');
  let displayName = $derived(userState.fullName || userState.username || '??');
  let initials = $derived(
    userState.fullName
      ? userState.fullName.split(' ').map((n: string) => n[0]).slice(0, 2).join('').toUpperCase()
      : userState.username ? userState.username.slice(0, 2).toUpperCase() : '??'
  );
  let avatarUrl = $derived(userState.avatarUrl);
</script>

<header class="flex items-center justify-between px-6 py-3.5 bg-bg-sidebar shadow-[0_1px_0_var(--color-border)] relative z-10">
  <h1 class="text-base font-semibold tracking-[-0.01em] text-text">{pageTitle}</h1>
  <div class="flex items-center gap-2.5">
    {#if avatarUrl}
      <img src={avatarUrl} alt={displayName} class="w-[30px] h-[30px] rounded-full object-cover" />
    {:else}
      <div
        class="w-[30px] h-[30px] rounded-full text-white text-[11px] font-bold flex items-center justify-center tracking-[0.02em]"
        style="background: linear-gradient(135deg, var(--color-primary-dim) 0%, var(--color-primary) 100%)"
      >{initials}</div>
    {/if}
    <span class="text-[13px] text-muted font-medium">{displayName}</span>
    {#if userState.isAdmin}
      <span class="text-[10px] px-2 py-0.5 rounded-full bg-primary-glow text-primary font-semibold uppercase tracking-[0.05em] border border-primary/20">admin</span>
    {/if}
    <button
      class="w-8 h-8 flex items-center justify-center border border-border rounded bg-transparent text-muted transition-all duration-150 hover:bg-danger-glow hover:border-danger hover:text-danger"
      onclick={logout}
      title="Logout"
    >
      <Icon name="log-out" size={16} />
    </button>
  </div>
</header>
