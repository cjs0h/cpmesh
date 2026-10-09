<script lang="ts">
  import Icon from '../Icon.svelte';
  import type { Tone } from '../../lib/format';

  /** Square, flat-filled icon container with an ink border and tiny hard shadow. */
  let { icon, tone = 'neutral', size = 36, iconSize, title, class: className = '' }: { icon: string; tone?: Tone; size?: number; iconSize?: number; title?: string; class?: string } = $props();

  const tones: Record<Tone, string> = {
    neutral: 'bg-surface-2',
    accent: 'bg-accent',
    cyan: 'bg-cyan',
    mint: 'bg-mint',
    gold: 'bg-yellow',
    rose: 'bg-rose',
    violet: 'bg-violet',
  };
</script>

<span class="inline-flex shrink-0 items-center justify-center rounded-md border-2 border-ink text-ink shadow-xs {tones[tone]} {className}" style="width: {size}px; height: {size}px;" {title}>
  <Icon name={icon} size={iconSize ?? Math.round(size * 0.44)} strokeWidth={2.4} />
</span>
