<script lang="ts">
  /** MagicUI Scroll Progress: a thin bar at the top tracking page scroll. */
  let { class: className = '' }: { class?: string } = $props();

  let progress = $state(0);

  $effect(() => {
    const update = () => {
      const doc = document.documentElement;
      const max = doc.scrollHeight - doc.clientHeight;
      progress = max > 0 ? Math.min(1, window.scrollY / max) : 0;
    };
    update();
    window.addEventListener('scroll', update, { passive: true });
    window.addEventListener('resize', update);
    return () => {
      window.removeEventListener('scroll', update);
      window.removeEventListener('resize', update);
    };
  });
</script>

<div class="pointer-events-none fixed inset-x-0 top-0 z-[60] h-1 bg-ink/10 {className}" aria-hidden="true">
  <div class="h-full origin-left bg-[linear-gradient(90deg,var(--color-yellow),var(--color-accent))] transition-transform duration-100 ease-linear" style="transform: scaleX({progress});"></div>
</div>
