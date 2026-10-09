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
    /** Lift on hover. */
    hover?: boolean;
    /** Colour of the hard shadow. */
    shadow?: 'ink' | Accent;
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
    shadow = 'ink',
    class: className = '',
    bodyClass = '',
    actions,
    children,
    ...rest
  }: Props = $props();

  const tiles: Record<Accent, string> = {
    accent: 'bg-accent',
    cyan: 'bg-cyan',
    mint: 'bg-mint',
    gold: 'bg-yellow',
    rose: 'bg-rose',
    violet: 'bg-violet',
    neutral: 'bg-surface-2',
  };

  const shadows: Record<'ink' | Accent, string> = {
    ink: 'var(--color-ink)',
    accent: 'var(--color-accent)',
    cyan: 'var(--color-cyan)',
    mint: 'var(--color-mint)',
    gold: 'var(--color-yellow)',
    rose: 'var(--color-rose)',
    violet: 'var(--color-violet)',
    neutral: 'var(--color-surface-3)',
  };
</script>

<section class="panel overflow-hidden {hover ? 'panel-hover' : ''} {className}" style="--panel-shadow: {shadows[shadow]};" {...rest}>
  {#if title || actions}
    <header class="flex items-center gap-3 border-b-2 border-ink bg-surface-2/60 px-5 py-3.5">
      {#if icon}
        <div class="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border-2 border-ink text-ink shadow-xs {tiles[accent]}">
          <Icon name={icon} size={17} strokeWidth={2.4} />
        </div>
      {/if}
      <div class="min-w-0 flex-1">
        {#if title}<h3 class="truncate font-head text-[15px] text-ink">{title}</h3>{/if}
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
