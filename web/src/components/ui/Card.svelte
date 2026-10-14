<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLAttributes } from 'svelte/elements';
  import Icon from '../Icon.svelte';

  type Accent = 'accent' | 'cyan' | 'mint' | 'gold' | 'rose' | 'violet' | 'neutral';

  interface Props extends HTMLAttributes<HTMLElement> {
    title?: string;
    description?: string;
    icon?: string;
    /** Kept for call-site compatibility; the monochrome theme renders all headers the same. */
    accent?: Accent;
    padded?: boolean;
    hover?: boolean;
    shadow?: string;
    class?: string;
    bodyClass?: string;
    actions?: Snippet;
    children: Snippet;
  }

  let { title, description, icon, accent: _accent = 'neutral', padded = true, hover = false, shadow: _shadow, class: className = '', bodyClass = '', actions, children, ...rest }: Props = $props();
</script>

<section class="overflow-hidden rounded-lg border border-border bg-surface {hover ? 'transition-[border-color,box-shadow] duration-150 hover:border-border-strong hover:shadow-sm' : ''} {className}" {...rest}>
  {#if title || actions}
    <header class="flex items-center gap-3 border-b border-border px-5 py-3.5">
      {#if icon}
        <span class="text-muted"><Icon name={icon} size={16} /></span>
      {/if}
      <div class="min-w-0 flex-1">
        {#if title}<h3 class="truncate text-sm font-medium text-fg">{title}</h3>{/if}
        {#if description}<p class="mt-0.5 text-[13px] text-muted">{description}</p>{/if}
      </div>
      {#if actions}
        <div class="flex shrink-0 items-center gap-2">{@render actions()}</div>
      {/if}
    </header>
  {/if}
  <div class="{padded ? 'p-5' : ''} {bodyClass}">
    {@render children()}
  </div>
</section>
