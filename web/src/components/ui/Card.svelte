<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { HTMLAttributes } from 'svelte/elements';
  import Icon from '../Icon.svelte';

  type Accent = 'accent' | 'cyan' | 'mint' | 'gold' | 'rose' | 'violet' | 'neutral';

  interface Props extends HTMLAttributes<HTMLElement> {
    title?: string;
    description?: string;
    icon?: string;
    accent?: Accent;
    /** Adds inner padding to the body. */
    padded?: boolean;
    /** Lift + brighten on hover. */
    hover?: boolean;
    class?: string;
    bodyClass?: string;
    actions?: Snippet;
    children: Snippet;
  }

  let {
    title,
    description,
    icon,
    accent = 'accent',
    padded = true,
    hover = false,
    class: className = '',
    bodyClass = '',
    actions,
    children,
    ...rest
  }: Props = $props();

  const tiles: Record<Accent, string> = {
    accent: 'bg-accent/12 border-accent/25 text-accent',
    cyan: 'bg-cyan/12 border-cyan/25 text-cyan',
    mint: 'bg-mint/12 border-mint/25 text-mint',
    gold: 'bg-gold/12 border-gold/25 text-gold',
    rose: 'bg-rose/12 border-rose/25 text-rose',
    violet: 'bg-violet/12 border-violet/25 text-violet',
    neutral: 'bg-surface-3 border-border-strong text-muted',
  };
</script>

<section
  class="rounded-xl border border-border bg-surface shadow-card {hover
    ? 'transition-[border-color,box-shadow,transform] duration-300 hover:-translate-y-0.5 hover:border-border-strong hover:shadow-pop'
    : ''} {className}"
  {...rest}
>
  {#if title || actions}
    <header class="flex items-center gap-3 border-b border-border px-5 py-4">
      {#if icon}
        <div class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border {tiles[accent]}">
          <Icon name={icon} size={17} />
        </div>
      {/if}
      <div class="min-w-0 flex-1">
        {#if title}<h3 class="truncate text-[15px] font-semibold tracking-tight text-fg">{title}</h3>{/if}
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
