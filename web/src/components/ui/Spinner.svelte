<script lang="ts">
  let { size = 20, class: className = '' }: { size?: number; class?: string } = $props();
</script>

<span
  class="inline-block shrink-0 rounded-full border-[3px] border-ink/20 border-t-ink animate-[spin_0.7s_linear_infinite] {className}"
  style="width: {size}px; height: {size}px;"
  role="status"
  aria-label="Loading"
></span>
