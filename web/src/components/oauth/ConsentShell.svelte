<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from '../Icon.svelte';
  import Logo from '../Logo.svelte';
  import Alert from '../ui/Alert.svelte';

  /**
   * A page of its own, without the dashboard around it, where an AI agent asks for
   * access to the account (`#/authorize`, `#/activate`).
   */
  let { title, subtitle, children }: { title: string; subtitle?: string; children: Snippet } = $props();

  // The server forbids framing these pages; don't offer the buttons if that got lost on the way
  const framed = window.self !== window.top;
</script>

<div class="flex min-h-dvh flex-col bg-bg-deep">
  <header class="flex h-14 items-center justify-between px-5 sm:px-8">
    <a href="#/" class="inline-flex items-center gap-2" aria-label="cpmesh dashboard">
      <Logo size={24} withText textClass="text-[15px]" />
    </a>
    <a href="#/" class="inline-flex items-center gap-1.5 text-[13px] text-muted transition-colors hover:text-fg">
      Dashboard <Icon name="arrow-right" size={14} />
    </a>
  </header>

  <main class="flex flex-1 items-center justify-center px-5 pb-16 pt-6 sm:px-8">
    <div class="w-full max-w-[440px]">
      <div class="mb-6 text-center">
        <h1 class="text-2xl font-semibold tracking-[-0.02em] text-fg">{title}</h1>
        {#if subtitle}<p class="mt-1.5 text-sm text-muted">{subtitle}</p>{/if}
      </div>
      <div class="rounded-lg border border-border bg-surface p-6 shadow-sm sm:p-7">
        {#if framed}
          <Alert tone="danger">For your security, this page only works in its own tab. Open the link directly in your browser.</Alert>
        {:else}
          {@render children()}
        {/if}
      </div>
    </div>
  </main>
</div>
