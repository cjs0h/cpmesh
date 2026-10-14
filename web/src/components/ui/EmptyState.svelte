<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from '../Icon.svelte';

  interface Props {
    icon?: string;
    title: string;
    description?: string;
    compact?: boolean;
    class?: string;
    children?: Snippet;
  }

  let { icon = 'inbox', title, description, compact = false, class: className = '', children }: Props = $props();
</script>

<div class="rounded-lg border border-dashed border-border-strong bg-bg-deep text-center {compact ? 'px-5 py-8' : 'px-6 py-14'} {className}">
  <div class="mx-auto mb-3 flex items-center justify-center rounded-full border border-border bg-surface text-muted {compact ? 'h-10 w-10' : 'h-12 w-12'}">
    <Icon name={icon} size={compact ? 18 : 20} strokeWidth={1.75} />
  </div>
  <p class="text-sm font-medium text-fg">{title}</p>
  {#if description}
    <p class="mx-auto mt-1 max-w-sm text-[13px] leading-relaxed text-muted">{description}</p>
  {/if}
  {#if children}
    <div class="mt-5 flex flex-wrap items-center justify-center gap-2">{@render children()}</div>
  {/if}
</div>
