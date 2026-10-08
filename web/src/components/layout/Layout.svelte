<script lang="ts">
  import type { Snippet } from 'svelte';
  import { router } from 'svelte-spa-router';
  import Sidebar from './Sidebar.svelte';
  import Header from './Header.svelte';
  import { routeFor } from '../../lib/routes';

  let { children }: { children: Snippet } = $props();
  const route = $derived(routeFor(router.location));
</script>

<div class="flex h-dvh overflow-hidden bg-bg">
  <Sidebar />

  <div class="relative flex min-w-0 flex-1 flex-col">
    <div class="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top_left,rgba(255,122,89,0.07),transparent_45%),radial-gradient(ellipse_at_bottom_right,rgba(73,198,229,0.06),transparent_50%)]"></div>
    <Header />
    <main class="relative flex-1 overflow-y-auto">
      <div class="mx-auto w-full max-w-[1200px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
        {#key router.location}
          <div class="animate-[fade-up_0.35s_var(--ease-out-expo)]">
            {#if route && !route.hideTitle}
              <div class="mb-6">
                <h1 class="font-display text-2xl font-semibold tracking-tight text-fg sm:text-[28px]">{route.label}</h1>
                <p class="mt-1 text-sm text-muted">{route.description}</p>
              </div>
            {/if}
            {@render children()}
          </div>
        {/key}
      </div>
    </main>
  </div>
</div>
