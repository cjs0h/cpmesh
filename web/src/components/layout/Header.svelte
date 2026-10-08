<script lang="ts">
  import { router } from 'svelte-spa-router';
  import { userState } from '../../lib/stores/user.svelte';
  import { openSidebar } from '../../lib/stores/ui.svelte';
  import { connectionState } from '../../lib/stores/connection.svelte';
  import { routeFor } from '../../lib/routes';
  import Icon from '../Icon.svelte';
  import Badge from '../ui/Badge.svelte';
  import Avatar from '../ui/Avatar.svelte';

  const route = $derived(routeFor(router.location));
  const title = $derived(route?.label ?? 'Not found');
  const displayName = $derived(userState.fullName || userState.username || '');
  const status = $derived(connectionState.status);
</script>

<header class="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-border bg-bg/80 px-4 backdrop-blur-xl sm:px-6 lg:px-8">
  <button
    type="button"
    class="-ml-1 flex h-9 w-9 items-center justify-center rounded-md text-muted transition-colors hover:bg-white/5 hover:text-fg lg:hidden"
    aria-label="Open navigation"
    onclick={openSidebar}
  >
    <Icon name="menu" size={20} />
  </button>

  <div class="min-w-0 flex-1">
    <div class="flex items-center gap-2 text-[11px] font-medium uppercase tracking-[0.12em] text-dim">
      <span>{route?.admin ? 'Admin' : 'Workspace'}</span>
      <Icon name="chevron-right" size={10} />
      <span class="truncate text-muted">{title}</span>
    </div>
  </div>

  <div class="flex items-center gap-2 sm:gap-3">
    <span class="hidden sm:contents">
      <Badge tone={status === 'online' ? 'mint' : status === 'offline' ? 'neutral' : 'gold'} dot live={status === 'online'}>
        {#if status === 'online'}Live{:else if status === 'offline'}Offline{:else}Syncing…{/if}
      </Badge>
    </span>
    {#if userState.isAdmin}
      <span class="hidden md:contents"><Badge tone="cyan" uppercase>admin</Badge></span>
    {/if}
    <a href="#/settings" class="flex items-center gap-2 rounded-full p-0.5 pr-2 transition-colors hover:bg-white/5" title="Account settings">
      <Avatar name={displayName} src={userState.avatarUrl} size={30} />
      <span class="hidden text-[13px] font-medium text-muted md:inline">{displayName}</span>
    </a>
  </div>
</header>
