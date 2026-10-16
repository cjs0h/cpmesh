<script lang="ts">
  import { router } from 'svelte-spa-router';
  import { userState, resetUserState } from '../../lib/stores/user.svelte';
  import { uiState, closeSidebar } from '../../lib/stores/ui.svelte';
  import { connectionState } from '../../lib/stores/connection.svelte';
  import { disconnectWS } from '../../lib/ws';
  import { appRoutes, isRouteActive } from '../../lib/routes';
  import Icon from '../Icon.svelte';
  import Logo from '../Logo.svelte';
  import Avatar from '../ui/Avatar.svelte';

  const primary = appRoutes.filter((r) => !r.admin);
  const admin = appRoutes.filter((r) => r.admin);

  const displayName = $derived(userState.fullName || userState.username || 'Account');
  const status = $derived(connectionState.status);

  // Close the drawer whenever the route changes (mobile).
  $effect(() => {
    void router.location;
    closeSidebar();
  });

  function logout() {
    disconnectWS();
    resetUserState();
    window.location.hash = '#/login';
  }
</script>

{#snippet navItem(route: (typeof appRoutes)[number])}
  {@const active = isRouteActive(route.path, router.location)}
  <li>
    <a
      href="#{route.path}"
      aria-current={active ? 'page' : undefined}
      class="flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-[13px] transition-colors duration-150 {active ? 'bg-surface-2 font-medium text-fg' : 'text-muted hover:bg-surface-2 hover:text-fg'}"
    >
      <span class={active ? 'text-fg' : 'text-dim'}><Icon name={route.icon} size={15} strokeWidth={1.75} /></span>
      {route.label}
    </a>
  </li>
{/snippet}

{#if uiState.sidebarOpen}
  <button type="button" class="fixed inset-0 z-40 bg-black/20 lg:hidden animate-[fade-in_0.15s_ease-out]" aria-label="Close navigation" onclick={closeSidebar}></button>
{/if}

<aside
  class="fixed inset-y-0 left-0 z-50 flex w-[240px] shrink-0 flex-col border-r border-border bg-surface transition-transform duration-200 ease-out lg:static lg:translate-x-0 {uiState.sidebarOpen ? 'translate-x-0 shadow-lg' : '-translate-x-full'}"
  aria-label="Main navigation"
>
  <div class="flex h-14 items-center justify-between px-4">
    <a href="#/" class="inline-flex items-center gap-2">
      <Logo size={24} withText textClass="text-[15px]" />
    </a>
    <button type="button" class="flex h-7 w-7 items-center justify-center rounded-md text-dim hover:bg-surface-2 hover:text-fg lg:hidden" aria-label="Close navigation" onclick={closeSidebar}>
      <Icon name="x" size={16} />
    </button>
  </div>

  <nav class="flex-1 overflow-y-auto px-2.5 pb-4 pt-1">
    <ul class="flex flex-col gap-0.5">
      {#each primary as route (route.path)}
        {@render navItem(route)}
      {/each}
    </ul>

    {#if userState.isAdmin}
      <p class="mb-1.5 mt-6 px-2.5 text-[11px] font-medium text-dim">Administration</p>
      <ul class="flex flex-col gap-0.5">
        {#each admin as route (route.path)}
          {@render navItem(route)}
        {/each}
      </ul>
    {/if}
  </nav>

  <div class="border-t border-border p-3">
    <div class="mb-2 flex items-center justify-between rounded-md px-2.5 py-1.5 text-[12px] text-muted">
      <span class="flex items-center gap-2">
        <span class="status-dot {status === 'online' ? 'text-accent' : status === 'offline' ? 'text-border-strong' : 'text-amber-500'}" data-live={status === 'online'}></span>
        {#if status === 'online'}Live sync{:else if status === 'connecting'}Connecting…{:else if status === 'reconnecting'}Reconnecting…{:else}Offline{/if}
      </span>
      <span class="font-mono text-[10px] uppercase text-dim">wss</span>
    </div>

    <div class="flex items-center gap-2.5 rounded-md px-2 py-1.5">
      <Avatar name={displayName} src={userState.avatarUrl} size={28} />
      <div class="min-w-0 flex-1">
        <p class="truncate text-[13px] font-medium text-fg">{displayName}</p>
        <p class="truncate text-[11px] text-dim">{userState.isAdmin ? 'Administrator' : userState.email || `@${userState.username}`}</p>
      </div>
      <button type="button" class="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-dim transition-colors hover:bg-surface-2 hover:text-fg" title="Sign out" aria-label="Sign out" onclick={logout}>
        <Icon name="log-out" size={14} />
      </button>
    </div>
  </div>
</aside>
