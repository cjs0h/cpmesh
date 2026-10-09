<script lang="ts" generics="T">
  import type { Snippet } from 'svelte';

  /** MagicUI Orbiting Circles: items evenly spaced on a circular path, rotating. */
  let {
    items,
    item,
    radius = 120,
    duration = 24,
    reverse = false,
    iconSize = 44,
    path = true,
    class: className = '',
  }: { items: T[]; item: Snippet<[T, number]>; radius?: number; duration?: number; reverse?: boolean; iconSize?: number; path?: boolean; class?: string } = $props();
</script>

{#if path}
  <svg class="pointer-events-none absolute inset-0 h-full w-full" aria-hidden="true">
    <circle cx="50%" cy="50%" r={radius} fill="none" stroke="rgba(17,17,17,0.35)" stroke-width="2" stroke-dasharray="6 8" />
  </svg>
{/if}
{#each items as entry, i (i)}
  <div
    class="animate-orbit absolute flex items-center justify-center {className}"
    style="--duration: {duration}; --radius: {radius}; --angle: {(360 / items.length) * i}; width: {iconSize}px; height: {iconSize}px; animation-direction: {reverse ? 'reverse' : 'normal'};"
  >
    {@render item(entry, i)}
  </div>
{/each}
