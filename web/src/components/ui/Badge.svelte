<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from '../Icon.svelte';

  type Tone = 'neutral' | 'accent' | 'cyan' | 'mint' | 'gold' | 'rose' | 'violet' | 'ink';

  interface Props {
    tone?: Tone;
    size?: 'sm' | 'md';
    dot?: boolean;
    live?: boolean;
    icon?: string;
    uppercase?: boolean;
    class?: string;
    title?: string;
    children: Snippet;
  }

  let { tone = 'neutral', size = 'sm', dot = false, live = false, icon, uppercase = false, class: className = '', title, children }: Props = $props();

  // Monochrome badges: hairline outline pills; only semantic states get a muted tint.
  const tones: Record<Tone, string> = {
    neutral: 'border-border bg-surface text-muted',
    accent: 'border-accent/30 bg-accent/5 text-accent',
    cyan: 'border-border bg-surface-2 text-fg',
    violet: 'border-border bg-surface-2 text-fg',
    mint: 'border-green-200 bg-green-50 text-green-700',
    gold: 'border-amber-200 bg-amber-50 text-amber-700',
    rose: 'border-red-200 bg-red-50 text-red-700',
    ink: 'border-ink bg-ink text-white',
  };
</script>

<span
  {title}
  class="inline-flex items-center gap-1.5 rounded-full border font-medium whitespace-nowrap {size === 'sm' ? 'px-2 py-px text-[11px]' : 'px-2.5 py-0.5 text-xs'} {uppercase ? 'uppercase tracking-[0.06em]' : ''} {tones[tone]} {className}"
>
  {#if dot}<span class="status-dot {tone === 'mint' ? 'text-green-600' : tone === 'gold' ? 'text-amber-500' : tone === 'rose' ? 'text-red-500' : 'text-dim'}" data-live={live}></span>{/if}
  {#if icon}<Icon name={icon} size={size === 'sm' ? 11 : 12} />{/if}
  {@render children()}
</span>
