<script lang="ts">
  import { untrack } from 'svelte';

  /**
   * MagicUI Number Ticker: counts from `start` to `value` with an ease-out
   * curve once the element scrolls into view.
   */
  let {
    value,
    start = 0,
    duration = 1400,
    delay = 0,
    decimals = 0,
    prefix = '',
    suffix = '',
    class: className = '',
  }: { value: number; start?: number; duration?: number; delay?: number; decimals?: number; prefix?: string; suffix?: string; class?: string } = $props();

  // `start` is intentionally read once as the initial displayed value.
  let shown = $state(untrack(() => start));
  let el = $state<HTMLElement | null>(null);
  let started = false;

  const format = (n: number) =>
    new Intl.NumberFormat(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals }).format(n);

  function run(to: number) {
    const from = shown;
    const reduce = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce || typeof requestAnimationFrame !== 'function') {
      shown = to;
      return;
    }
    const t0 = performance.now() + delay;
    const tick = (now: number) => {
      const p = Math.min(1, Math.max(0, (now - t0) / duration));
      const eased = 1 - Math.pow(1 - p, 4);
      shown = from + (to - from) * eased;
      if (p < 1) requestAnimationFrame(tick);
      else shown = to;
    };
    requestAnimationFrame(tick);
  }

  // Start when visible; afterwards follow value changes directly.
  $effect(() => {
    const node = el;
    const target = value;
    if (!node) return;
    if (started) {
      run(target);
      return;
    }
    if (typeof IntersectionObserver === 'undefined') {
      started = true;
      run(target);
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          started = true;
          run(target);
          io.disconnect();
        }
      },
      { threshold: 0.3 }
    );
    io.observe(node);
    return () => io.disconnect();
  });
</script>

<span bind:this={el} class="tabular-nums {className}">{prefix}{format(shown)}{suffix}</span>
