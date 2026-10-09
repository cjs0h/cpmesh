<script lang="ts">
  /** MagicUI Meteors: streaks falling diagonally across a dark panel. */
  let {
    number = 16,
    minDelay = 0.2,
    maxDelay = 1.2,
    minDuration = 2,
    maxDuration = 8,
    angle = 215,
    color = '#ffd93d',
    class: className = '',
  }: { number?: number; minDelay?: number; maxDelay?: number; minDuration?: number; maxDuration?: number; angle?: number; color?: string; class?: string } = $props();

  // Seeded so SSR/hydration (if ever) and re-renders stay stable.
  function rand(i: number, salt: number) {
    const x = Math.sin(i * 12.9898 + salt * 78.233) * 43758.5453;
    return x - Math.floor(x);
  }

  const meteors = $derived(
    Array.from({ length: number }, (_, i) => ({
      left: `${Math.round(rand(i, 1) * 100)}%`,
      delay: `${(rand(i, 2) * (maxDelay - minDelay) + minDelay).toFixed(2)}s`,
      duration: `${Math.floor(rand(i, 3) * (maxDuration - minDuration) + minDuration)}s`,
    }))
  );
</script>

<div class="pointer-events-none absolute inset-0 overflow-hidden {className}" aria-hidden="true">
  {#each meteors as m, i (i)}
    <span
      class="animate-meteor absolute -top-[5%] h-0.5 w-0.5 rounded-full"
      style="left: {m.left}; --angle: -{angle}deg; --meteor-duration: {m.duration}; animation-delay: {m.delay}; background: {color}; box-shadow: 0 0 0 1px rgba(255,255,255,0.1);"
    >
      <span class="absolute top-1/2 -z-10 h-px w-[50px] -translate-y-1/2" style="background: linear-gradient(90deg, {color}, transparent);"></span>
    </span>
  {/each}
</div>
