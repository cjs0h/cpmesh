<script lang="ts">
  /** MagicUI Word Rotate: cycles through words with a vertical flip. */
  let { words, interval = 2400, class: className = '' }: { words: string[]; interval?: number; class?: string } = $props();

  let index = $state(0);
  let leaving = $state(false);

  $effect(() => {
    if (words.length < 2) return;
    const reduce = typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce) return;
    const id = setInterval(() => {
      leaving = true;
      setTimeout(() => {
        index = (index + 1) % words.length;
        leaving = false;
      }, 260);
    }, interval);
    return () => clearInterval(id);
  });

  const longest = $derived(words.reduce((a, b) => (b.length > a.length ? b : a), ''));
</script>

<span class="relative inline-grid overflow-hidden align-bottom [perspective:600px] {className}">
  <!-- Invisible widest word reserves the width so the layout never shifts. -->
  <span class="invisible col-start-1 row-start-1 whitespace-nowrap" aria-hidden="true">{longest}</span>
  {#key index}
    <span class="col-start-1 row-start-1 whitespace-nowrap {leaving ? 'animate-[word-out_0.26s_ease-in_forwards]' : 'animate-[word-in_0.4s_var(--ease-out-expo)]'}">{words[index]}</span>
  {/key}
</span>
