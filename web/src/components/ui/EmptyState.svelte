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

<div class="relative overflow-hidden rounded-md border-2 border-dashed border-ink bg-surface text-center {compact ? 'px-5 py-8' : 'px-6 py-14'} {className}">
  <div class="dot-grid pointer-events-none absolute inset-0 opacity-50 [mask-image:radial-gradient(ellipse_at_center,black,transparent_70%)]"></div>
  <div class="relative">
    <div class="mx-auto mb-4 flex items-center justify-center rounded-md border-2 border-ink bg-yellow text-ink shadow-sm animate-wiggle {compact ? 'h-11 w-11' : 'h-14 w-14'}">
      <Icon name={icon} size={compact ? 20 : 26} strokeWidth={2.2} />
    </div>
    <p class="font-head text-[15px] text-ink">{title}</p>
    {#if description}
      <p class="mx-auto mt-1.5 max-w-sm text-[13px] leading-relaxed text-muted">{description}</p>
    {/if}
    {#if children}
      <div class="mt-5 flex flex-wrap items-center justify-center gap-2">{@render children()}</div>
    {/if}
  </div>
</div>
