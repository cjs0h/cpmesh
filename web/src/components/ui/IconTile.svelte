<script lang="ts">
  import Icon from '../Icon.svelte';
  import type { Tone } from '../../lib/format';

  /** Square icon container. Monochrome: a hairline box with a muted glyph. */
  let { icon, tone: _tone = 'neutral', size = 36, iconSize, title, class: className = '' }: { icon: string; tone?: Tone; size?: number; iconSize?: number; title?: string; class?: string } = $props();
</script>

<span class="inline-flex shrink-0 items-center justify-center rounded-md border border-border bg-bg-deep text-muted {className}" style="width: {size}px; height: {size}px;" {title}>
  <Icon name={icon} size={iconSize ?? Math.round(size * 0.44)} strokeWidth={1.75} />
</span>
