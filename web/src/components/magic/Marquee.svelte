<script lang="ts">
  import type { Snippet } from 'svelte';

  /** MagicUI Marquee: content repeated and scrolled infinitely; pauses on hover. */
  let {
    reverse = false,
    pauseOnHover = true,
    vertical = false,
    repeat = 4,
    duration = 40,
    gap = '1rem',
    class: className = '',
    children,
  }: { reverse?: boolean; pauseOnHover?: boolean; vertical?: boolean; repeat?: number; duration?: number; gap?: string; class?: string; children: Snippet } = $props();
</script>

<div
  class="group flex overflow-hidden p-2 {vertical ? 'flex-col' : 'flex-row'} {className}"
  style="--duration: {duration}s; --gap: {gap}; gap: var(--gap);"
>
  {#each Array(repeat) as _, i (i)}
    <div
      class="flex shrink-0 justify-around {vertical ? 'animate-marquee-vertical flex-col' : 'animate-marquee flex-row'} {pauseOnHover ? 'group-hover:[animation-play-state:paused]' : ''}"
      style="gap: var(--gap); animation-direction: {reverse ? 'reverse' : 'normal'};"
      aria-hidden={i > 0 ? 'true' : undefined}
    >
      {@render children()}
    </div>
  {/each}
</div>
