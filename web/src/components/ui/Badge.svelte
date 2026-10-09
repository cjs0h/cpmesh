<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from '../Icon.svelte';

  type Tone = 'neutral' | 'accent' | 'cyan' | 'mint' | 'gold' | 'rose' | 'violet' | 'ink';

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

  // RetroUI badge: flat fill, ink border, 2px hard shadow.
  const tones: Record<Tone, string> = {
    neutral: 'bg-surface-2 text-ink',
    accent: 'bg-accent text-ink',
    cyan: 'bg-cyan text-ink',
    mint: 'bg-mint text-ink',
    gold: 'bg-yellow text-ink',
    rose: 'bg-rose text-ink',
    violet: 'bg-violet text-ink',
    ink: 'bg-ink text-cream',
  };
</script>

<span
  {title}
  class="inline-flex items-center gap-1.5 rounded-sm border-2 border-ink font-head whitespace-nowrap shadow-xs {size === 'sm'
    ? 'px-1.5 py-px text-[10.5px]'
    : 'px-2.5 py-1 text-xs'} {uppercase ? 'uppercase tracking-[0.08em]' : ''} {tones[tone]} {className}"
>
  {#if dot}<span class="status-dot {tone === 'mint' ? 'text-ink' : ''}" data-live={live}></span>{/if}
  {#if icon}<Icon name={icon} size={size === 'sm' ? 11 : 13} strokeWidth={2.5} />{/if}
  {@render children()}
</span>
