<script lang="ts">
  /** Brand mark: three mesh nodes on a yellow tile with an ink border and hard shadow. */
  let { size = 32, withText = false, textClass = '', class: className = '' }: { size?: number; withText?: boolean; textClass?: string; class?: string } = $props();
</script>

<span class="inline-flex items-center gap-2.5 {className}">
  <span
    class="relative inline-flex shrink-0 items-center justify-center overflow-hidden rounded-[22%] border-2 border-ink bg-yellow"
    style="width: {size}px; height: {size}px; box-shadow: {Math.max(2, Math.round(size / 12))}px {Math.max(2, Math.round(size / 12))}px 0 0 var(--color-ink);"
  >
    <svg viewBox="0 0 32 32" width={size} height={size} fill="none" aria-hidden="true">
      <path d="M10 22 L16 11 L22 22 Z" stroke="#111" stroke-width="2.4" stroke-linejoin="round" fill="#ff7a59" />
      <circle cx="16" cy="11" r="3" fill="#fffaf0" stroke="#111" stroke-width="2" />
      <circle cx="10" cy="22" r="3" fill="#fffaf0" stroke="#111" stroke-width="2" />
      <circle cx="22" cy="22" r="3" fill="#fffaf0" stroke="#111" stroke-width="2" />
    </svg>
  </span>
  {#if withText}
    <span class="font-head tracking-tight text-ink {textClass}">cpmesh</span>
  {/if}
</span>
