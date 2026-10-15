<script lang="ts">
  import type { Snippet } from 'svelte';
  import { router } from 'svelte-spa-router';
  import Sidebar from './Sidebar.svelte';
  import Header from './Header.svelte';
  import AnnouncementBanner from './AnnouncementBanner.svelte';
  import { routeFor } from '../../lib/routes';

  let { children }: { children: Snippet } = $props();
  const route = $derived(routeFor(router.location));
</script>

<div class="flex h-dvh overflow-hidden bg-bg-deep">
  <Sidebar />

  <div class="flex min-w-0 flex-1 flex-col">
    <Header />
    <AnnouncementBanner />
    <main class="flex-1 overflow-y-auto">
      <!-- Fluid container so large monitors are used without stretching line lengths -->
      <div class="mx-auto w-full max-w-[1200px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8 2xl:max-w-[1440px] 3xl:max-w-[1600px]">
        {#key router.location}
          <div>
            {#if route && !route.hideTitle}
              <div class="mb-6">
                <h1 class="text-xl font-semibold tracking-tight text-fg">{route.label}</h1>
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
