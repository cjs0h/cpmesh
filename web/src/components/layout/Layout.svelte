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
    <div class="dot-grid pointer-events-none absolute inset-0 opacity-40 [mask-image:linear-gradient(180deg,black,transparent_70%)]"></div>
    <Header />
    <main class="relative flex-1 overflow-y-auto">
      <!-- Fluid container: comfortable on laptops, fills 4K monitors without ballooning -->
      <div class="mx-auto w-full max-w-[1200px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8 2xl:max-w-[1500px] 2xl:px-12 3xl:max-w-[1700px]">
        {#key router.location}
          <div class="animate-[fade-up_0.35s_var(--ease-out-expo)]">
            {#if route && !route.hideTitle}
              <div class="mb-6">
                <h1 class="font-head text-2xl text-ink sm:text-[30px]">{route.label}</h1>
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
