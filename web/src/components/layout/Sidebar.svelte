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
    window.location.reload();
  }
</script>

{#snippet navItem(route: (typeof appRoutes)[number], fill: string)}
  {@const active = isRouteActive(route.path, router.location)}
  <li>
    <a
      href="#{route.path}"
      aria-current={active ? 'page' : undefined}
      class="group flex items-center gap-3 rounded-md border-2 px-3 py-2 font-head text-[12.5px] uppercase tracking-[0.04em] transition-[transform,box-shadow,background-color,border-color] duration-150 {active
        ? `border-ink ${fill} text-ink shadow-sm`
        : 'border-transparent text-muted hover:-translate-x-px hover:-translate-y-px hover:border-ink hover:bg-surface hover:text-ink hover:shadow-sm'}"
    >
      <span class="flex h-7 w-7 items-center justify-center rounded border-2 transition-colors {active ? 'border-ink bg-cream' : 'border-transparent group-hover:border-ink'}">
        <Icon name={route.icon} size={15} strokeWidth={2.4} />
      </span>
      {route.label}
    </a>
  </li>
{/snippet}

{#if uiState.sidebarOpen}
  <button type="button" class="fixed inset-0 z-40 bg-ink/50 lg:hidden animate-[fade-in_0.2s_ease-out]" aria-label="Close navigation" onclick={closeSidebar}></button>
{/if}

<aside
  class="fixed inset-y-0 left-0 z-50 flex w-[272px] shrink-0 flex-col border-r-2 border-ink bg-surface transition-transform duration-300 ease-[var(--ease-out-expo)] lg:static lg:translate-x-0 {uiState.sidebarOpen
    ? 'translate-x-0 shadow-pop'
    : '-translate-x-full'}"
  aria-label="Main navigation"
>
  <div class="flex items-center justify-between border-b-2 border-ink px-5 py-4">
    <a href="#/" class="inline-flex items-center gap-2.5">
      <Logo size={36} withText textClass="text-[18px]" />
    </a>
    <button type="button" class="flex h-8 w-8 items-center justify-center rounded border-2 border-ink bg-cream text-ink shadow-xs lg:hidden" aria-label="Close navigation" onclick={closeSidebar}>
      <Icon name="x" size={16} strokeWidth={2.5} />
    </button>
  </div>

  <nav class="flex-1 overflow-y-auto px-3 py-4">
    <ul class="flex flex-col gap-1">
      {#each primary as route (route.path)}
        {@render navItem(route, 'bg-yellow')}
      {/each}
    </ul>

    {#if userState.isAdmin}
      <p class="mb-2 mt-6 px-3 font-head text-[10px] uppercase tracking-[0.16em] text-dim">Administration</p>
      <ul class="flex flex-col gap-1">
        {#each admin as route (route.path)}
          {@render navItem(route, 'bg-cyan')}
        {/each}
      </ul>
    {/if}
  </nav>

  <div class="border-t-2 border-ink p-3">
    <!-- Connection status -->
    <div class="mb-3 flex items-center justify-between rounded-md border-2 border-ink px-3 py-2 font-mono text-[11.5px] shadow-xs {status === 'online' ? 'bg-mint' : status === 'offline' ? 'bg-surface-2' : 'bg-yellow'}">
      <span class="flex items-center gap-2 font-semibold text-ink">
        <span class="status-dot text-ink" data-live={status === 'online'}></span>
        {#if status === 'online'}LIVE SYNC{:else if status === 'connecting'}CONNECTING…{:else if status === 'reconnecting'}RECONNECTING…{:else}OFFLINE{/if}
      </span>
      <span class="text-[10px] uppercase tracking-wider text-ink/60">wss</span>
    </div>

    <!-- User card -->
    <div class="flex items-center gap-3 rounded-md px-1 py-1">
      <Avatar name={displayName} src={userState.avatarUrl} size={36} />
      <div class="min-w-0 flex-1">
        <p class="truncate font-head text-[12.5px] text-ink">{displayName}</p>
        <p class="truncate text-[11.5px] text-dim">{userState.isAdmin ? 'Administrator' : userState.email || `@${userState.username}`}</p>
      </div>
      <button
        type="button"
        class="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border-2 border-ink bg-surface text-ink shadow-xs transition-[transform,box-shadow,background-color] hover:-translate-x-px hover:-translate-y-px hover:bg-rose hover:shadow-sm active:translate-x-px active:translate-y-px active:shadow-none"
        title="Sign out"
        aria-label="Sign out"
        onclick={logout}
      >
        <Icon name="log-out" size={16} strokeWidth={2.4} />
      </button>
    </div>
  </div>
</aside>
