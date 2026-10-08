<script lang="ts">
  import Icon from '../Icon.svelte';
  import type { Tone } from '../../lib/format';

  /** Square, tinted icon container used for list rows and card headers. */
  let { icon, tone = 'neutral', size = 36, iconSize, title, class: className = '' }: { icon: string; tone?: Tone; size?: number; iconSize?: number; title?: string; class?: string } = $props();

  const tones: Record<Tone, string> = {
    neutral: 'bg-surface-3 border-border-strong text-muted',
    accent: 'bg-accent/12 border-accent/25 text-accent',
    cyan: 'bg-cyan/12 border-cyan/25 text-cyan',
    mint: 'bg-mint/12 border-mint/25 text-mint',
    gold: 'bg-gold/12 border-gold/25 text-gold',
    rose: 'bg-rose/12 border-rose/25 text-rose',
    violet: 'bg-violet/12 border-violet/25 text-violet',
  };
</script>

<span
  class="inline-flex shrink-0 items-center justify-center rounded-lg border {tones[tone]} {className}"
  style="width: {size}px; height: {size}px;"
  {title}
>
  <Icon name={icon} size={iconSize ?? Math.round(size * 0.44)} />
</span>
