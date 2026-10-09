<script lang="ts">
  import type { Snippet } from 'svelte';

  interface Props {
    title: string;
    description?: string;
    eyebrow?: string;
    class?: string;
    actions?: Snippet;
  }

  let { title, description, eyebrow, class: className = '', actions }: Props = $props();
</script>

<div class="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between {className}">
  <div class="min-w-0">
    {#if eyebrow}<p class="mb-1 text-xs font-medium text-muted">{eyebrow}</p>{/if}
    <h2 class="text-xl font-semibold tracking-tight text-fg">{title}</h2>
    {#if description}<p class="mt-1 max-w-2xl text-sm text-muted">{description}</p>{/if}
  </div>
  {#if actions}
    <div class="flex shrink-0 flex-wrap items-center gap-2">{@render actions()}</div>
  {/if}
</div>
