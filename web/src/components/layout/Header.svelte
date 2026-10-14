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

<header class="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-surface px-4 sm:px-6 lg:px-8">
  <button type="button" class="-ml-1 flex h-8 w-8 items-center justify-center rounded-md text-muted hover:bg-surface-2 hover:text-fg lg:hidden" aria-label="Open navigation" onclick={openSidebar}>
    <Icon name="menu" size={18} />
  </button>

  <div class="flex min-w-0 flex-1 items-center gap-1.5 text-[13px]">
    <span class="text-dim">{route?.admin ? 'Admin' : 'Workspace'}</span>
    <span class="text-border-strong">/</span>
    <span class="truncate font-medium text-fg">{title}</span>
  </div>

  <div class="flex items-center gap-2 sm:gap-3">
    <span class="hidden sm:contents">
      <Badge tone={status === 'online' ? 'mint' : status === 'offline' ? 'neutral' : 'gold'} dot live={status === 'online'}>
        {#if status === 'online'}Live{:else if status === 'offline'}Offline{:else}Syncing…{/if}
      </Badge>
    </span>
    {#if userState.isAdmin}
      <span class="hidden md:contents"><Badge tone="neutral">Admin</Badge></span>
    {/if}
    <a href="#/settings" class="flex items-center gap-2 rounded-full p-0.5 pr-2 transition-colors hover:bg-surface-2" title="Account settings">
      <Avatar name={displayName} src={userState.avatarUrl} size={26} />
      <span class="hidden text-[13px] text-fg md:inline">{displayName}</span>
    </a>
  </div>
</header>
