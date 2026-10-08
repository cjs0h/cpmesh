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

{#if uiState.sidebarOpen}
  <button
    type="button"
    class="fixed inset-0 z-40 bg-bg-deep/70 backdrop-blur-sm lg:hidden animate-[fade-in_0.2s_ease-out]"
    aria-label="Close navigation"
    onclick={closeSidebar}
  ></button>
{/if}

<aside
  class="fixed inset-y-0 left-0 z-50 flex w-[268px] shrink-0 flex-col border-r border-border bg-[#0a1324] transition-transform duration-300 ease-[var(--ease-out-expo)] lg:static lg:translate-x-0 {uiState.sidebarOpen
    ? 'translate-x-0 shadow-pop'
    : '-translate-x-full'}"
  aria-label="Main navigation"
>
  <div class="flex items-center justify-between px-5 pb-4 pt-5">
    <a href="#/" class="inline-flex items-center gap-2.5">
      <Logo size={34} withText textClass="text-[17px]" />
    </a>
    <button type="button" class="flex h-8 w-8 items-center justify-center rounded-md text-dim hover:bg-white/5 hover:text-fg lg:hidden" aria-label="Close navigation" onclick={closeSidebar}>
      <Icon name="x" size={16} />
    </button>
  </div>

  <nav class="flex-1 overflow-y-auto px-3 pb-4">
    <ul class="flex flex-col gap-0.5">
      {#each primary as route (route.path)}
        {@const active = isRouteActive(route.path, router.location)}
        <li>
          <a
            href="#{route.path}"
            aria-current={active ? 'page' : undefined}
            class="group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-[13.5px] font-medium transition-colors duration-150 {active
              ? 'bg-accent/10 text-fg'
              : 'text-muted hover:bg-white/[0.04] hover:text-fg'}"
          >
            {#if active}
              <span class="absolute inset-y-2 -left-3 w-[3px] rounded-r-full bg-accent shadow-[0_0_12px_rgba(255,122,89,0.8)]"></span>
            {/if}
            <span class="transition-colors {active ? 'text-accent' : 'text-dim group-hover:text-muted'}"><Icon name={route.icon} size={17} /></span>
            {route.label}
          </a>
        </li>
      {/each}
    </ul>

    {#if userState.isAdmin}
      <p class="mb-1.5 mt-6 px-3 text-[10.5px] font-semibold uppercase tracking-[0.14em] text-dim">Administration</p>
      <ul class="flex flex-col gap-0.5">
        {#each admin as route (route.path)}
          {@const active = isRouteActive(route.path, router.location)}
          <li>
            <a
              href="#{route.path}"
              aria-current={active ? 'page' : undefined}
              class="group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-[13.5px] font-medium transition-colors duration-150 {active
                ? 'bg-cyan/10 text-fg'
                : 'text-muted hover:bg-white/[0.04] hover:text-fg'}"
            >
              {#if active}
                <span class="absolute inset-y-2 -left-3 w-[3px] rounded-r-full bg-cyan shadow-[0_0_12px_rgba(73,198,229,0.8)]"></span>
              {/if}
              <span class="transition-colors {active ? 'text-cyan' : 'text-dim group-hover:text-muted'}"><Icon name={route.icon} size={17} /></span>
              {route.label}
            </a>
          </li>
        {/each}
      </ul>
    {/if}
  </nav>

  <div class="border-t border-border p-3">
    <!-- Connection status -->
    <div class="mb-3 flex items-center justify-between rounded-lg border border-border bg-surface px-3 py-2 text-[12px]">
      <span class="flex items-center gap-2 font-medium {status === 'online' ? 'text-mint' : status === 'offline' ? 'text-dim' : 'text-gold'}">
        <span class="status-dot" data-live={status === 'online'}></span>
        {#if status === 'online'}Live sync{:else if status === 'connecting'}Connecting…{:else if status === 'reconnecting'}Reconnecting…{:else}Offline{/if}
      </span>
      <span class="font-mono text-[10px] uppercase tracking-wider text-dim">wss</span>
    </div>

    <!-- User card -->
    <div class="flex items-center gap-3 rounded-lg px-2 py-1.5">
      <Avatar name={displayName} src={userState.avatarUrl} size={34} />
      <div class="min-w-0 flex-1">
        <p class="truncate text-[13px] font-semibold text-fg">{displayName}</p>
        <p class="truncate text-[11.5px] text-dim">{userState.isAdmin ? 'Administrator' : userState.email || `@${userState.username}`}</p>
      </div>
      <button
        type="button"
        class="flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-dim transition-colors hover:bg-rose/10 hover:text-rose"
        title="Sign out"
        aria-label="Sign out"
        onclick={logout}
      >
        <Icon name="log-out" size={16} />
      </button>
    </div>
  </div>
</aside>
