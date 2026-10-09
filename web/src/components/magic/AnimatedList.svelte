<script lang="ts" generics="T">
  import type { Snippet } from 'svelte';

  /**
   * MagicUI Animated List: reveals items one at a time (newest on top) and
   * keeps the latest `visible` entries, cycling forever.
   */
  let {
    items,
    item,
    visible = 3,
    interval = 1800,
    class: className = '',
  }: { items: T[]; item: Snippet<[T, number]>; visible?: number; interval?: number; class?: string } = $props();

  let shown = $state<Array<{ id: number; value: T }>>([]);
  let counter = 0;

  $effect(() => {
    if (items.length === 0) return;
    const push = () => {
      const value = items[counter % items.length];
      shown = [{ id: counter, value }, ...shown].slice(0, visible);
      counter += 1;
    };
    push();
    const id = setInterval(push, interval);
    return () => clearInterval(id);
  });
</script>

<ul class="flex flex-col gap-2 {className}">
  {#each shown as entry, i (entry.id)}
    <li class="animate-[fade-up_0.45s_var(--ease-out-expo)] transition-[opacity,transform] duration-500" style="opacity: {1 - i * 0.25}; transform: scale({1 - i * 0.03});">
      {@render item(entry.value, i)}
    </li>
  {/each}
</ul>
