<script lang="ts">
  import { link, location } from 'svelte-spa-router';
  import { userState } from '../../lib/stores/user.svelte';
  import Icon from '../Icon.svelte';

  function isActive(path: string): boolean {
    if (path === '/') return $location === '/';
    return $location.startsWith(path);
  }
</script>

<aside class="w-[232px] bg-bg-sidebar border-r border-border flex flex-col shrink-0 overflow-y-auto">
  <div class="flex items-center gap-2.5 px-5 pt-5 pb-4 border-b border-border mb-2">
    <div
      class="w-8 h-8 rounded flex items-center justify-center text-white shadow-[0_2px_8px_rgba(129,140,248,0.3)]"
      style="background: linear-gradient(135deg, var(--color-primary) 0%, var(--color-primary-dim) 100%)"
    >
      <Icon name="network" size={18} />
    </div>
    <span class="text-lg font-bold tracking-[-0.03em] text-text">cpmesh</span>
  </div>

  <nav class="flex flex-col gap-0.5 px-2.5 py-1">
    <a href="/" use:link class="flex items-center gap-2.5 py-[9px] px-3 rounded text-[13.5px] font-medium no-underline transition-all duration-150 relative border-l-3 -ml-[3px] {isActive('/') ? 'bg-primary-glow text-primary border-l-primary' : 'text-muted border-l-transparent hover:bg-bg-hover hover:text-text hover:no-underline'}">
      <Icon name="dashboard" size={18} /> <span>Dashboard</span>
    </a>
    <a href="/clipboard" use:link class="flex items-center gap-2.5 py-[9px] px-3 rounded text-[13.5px] font-medium no-underline transition-all duration-150 relative border-l-3 -ml-[3px] {isActive('/clipboard') ? 'bg-primary-glow text-primary border-l-primary' : 'text-muted border-l-transparent hover:bg-bg-hover hover:text-text hover:no-underline'}">
      <Icon name="clipboard" size={18} /> <span>Clipboard</span>
    </a>
    <a href="/devices" use:link class="flex items-center gap-2.5 py-[9px] px-3 rounded text-[13.5px] font-medium no-underline transition-all duration-150 relative border-l-3 -ml-[3px] {isActive('/devices') ? 'bg-primary-glow text-primary border-l-primary' : 'text-muted border-l-transparent hover:bg-bg-hover hover:text-text hover:no-underline'}">
      <Icon name="monitor" size={18} /> <span>Devices</span>
    </a>
    <a href="/settings" use:link class="flex items-center gap-2.5 py-[9px] px-3 rounded text-[13.5px] font-medium no-underline transition-all duration-150 relative border-l-3 -ml-[3px] {isActive('/settings') ? 'bg-primary-glow text-primary border-l-primary' : 'text-muted border-l-transparent hover:bg-bg-hover hover:text-text hover:no-underline'}">
      <Icon name="settings" size={18} /> <span>Settings</span>
    </a>

    {#if userState.isAdmin}
      <div class="px-3 pt-5 pb-1.5 text-[11px] uppercase tracking-[0.08em] text-dim font-semibold">Admin</div>
      <a href="/admin/users" use:link class="flex items-center gap-2.5 py-[9px] px-3 rounded text-[13.5px] font-medium no-underline transition-all duration-150 relative border-l-3 -ml-[3px] {isActive('/admin/users') ? 'bg-primary-glow text-primary border-l-primary' : 'text-muted border-l-transparent hover:bg-bg-hover hover:text-text hover:no-underline'}">
        <Icon name="users" size={18} /> <span>Users</span>
      </a>
      <a href="/admin/plans" use:link class="flex items-center gap-2.5 py-[9px] px-3 rounded text-[13.5px] font-medium no-underline transition-all duration-150 relative border-l-3 -ml-[3px] {isActive('/admin/plans') ? 'bg-primary-glow text-primary border-l-primary' : 'text-muted border-l-transparent hover:bg-bg-hover hover:text-text hover:no-underline'}">
        <Icon name="star" size={18} /> <span>Plans</span>
      </a>
      <a href="/admin/downloads" use:link class="flex items-center gap-2.5 py-[9px] px-3 rounded text-[13.5px] font-medium no-underline transition-all duration-150 relative border-l-3 -ml-[3px] {isActive('/admin/downloads') ? 'bg-primary-glow text-primary border-l-primary' : 'text-muted border-l-transparent hover:bg-bg-hover hover:text-text hover:no-underline'}">
        <Icon name="download" size={18} /> <span>Downloads</span>
      </a>
      <a href="/admin/releases" use:link class="flex items-center gap-2.5 py-[9px] px-3 rounded text-[13.5px] font-medium no-underline transition-all duration-150 relative border-l-3 -ml-[3px] {isActive('/admin/releases') ? 'bg-primary-glow text-primary border-l-primary' : 'text-muted border-l-transparent hover:bg-bg-hover hover:text-text hover:no-underline'}">
        <Icon name="upload" size={18} /> <span>Releases</span>
      </a>
      <a href="/admin/settings" use:link class="flex items-center gap-2.5 py-[9px] px-3 rounded text-[13.5px] font-medium no-underline transition-all duration-150 relative border-l-3 -ml-[3px] {isActive('/admin/settings') ? 'bg-primary-glow text-primary border-l-primary' : 'text-muted border-l-transparent hover:bg-bg-hover hover:text-text hover:no-underline'}">
        <Icon name="sliders" size={18} /> <span>Site Settings</span>
      </a>
      <a href="/admin/stats" use:link class="flex items-center gap-2.5 py-[9px] px-3 rounded text-[13.5px] font-medium no-underline transition-all duration-150 relative border-l-3 -ml-[3px] {isActive('/admin/stats') ? 'bg-primary-glow text-primary border-l-primary' : 'text-muted border-l-transparent hover:bg-bg-hover hover:text-text hover:no-underline'}">
        <Icon name="bar-chart" size={18} /> <span>Stats</span>
      </a>
    {/if}
  </nav>
</aside>
