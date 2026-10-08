<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from '../Icon.svelte';

  type Tone = 'neutral' | 'accent' | 'cyan' | 'mint' | 'gold' | 'rose' | 'violet';

  interface Props {
    tone?: Tone;
    size?: 'sm' | 'md';
    /** Shows a small status dot before the label; `live` adds a pulsing halo. */
    dot?: boolean;
    live?: boolean;
    icon?: string;
    uppercase?: boolean;
    class?: string;
    title?: string;
    children: Snippet;
  }

  let { tone = 'neutral', size = 'sm', dot = false, live = false, icon, uppercase = false, class: className = '', title, children }: Props = $props();

  const tones: Record<Tone, string> = {
    neutral: 'bg-surface-3 text-muted border-border-strong',
    accent: 'bg-accent/12 text-accent border-accent/25',
    cyan: 'bg-cyan/12 text-cyan border-cyan/25',
    mint: 'bg-mint/12 text-mint border-mint/25',
    gold: 'bg-gold/12 text-gold border-gold/25',
    rose: 'bg-rose/12 text-rose border-rose/25',
    violet: 'bg-violet/12 text-violet border-violet/25',
  };
</script>

<span
  {title}
  class="inline-flex items-center gap-1.5 rounded-full border font-semibold whitespace-nowrap {size === 'sm'
    ? 'px-2 py-0.5 text-[11px]'
    : 'px-2.5 py-1 text-xs'} {uppercase ? 'uppercase tracking-[0.06em]' : ''} {tones[tone]} {className}"
>
  {#if dot}<span class="status-dot" data-live={live}></span>{/if}
  {#if icon}<Icon name={icon} size={size === 'sm' ? 11 : 13} />{/if}
  {@render children()}
</span>
