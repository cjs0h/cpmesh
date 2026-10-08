<script lang="ts">
  /** Brand mark: three mesh nodes joined by an encrypted link. */
  let { size = 32, withText = false, textClass = '', class: className = '' }: { size?: number; withText?: boolean; textClass?: string; class?: string } = $props();
  const uid = $props.id();
</script>

<span class="inline-flex items-center gap-2.5 {className}">
  <span
    class="relative inline-flex shrink-0 items-center justify-center overflow-hidden rounded-[28%] border border-white/10 shadow-[0_8px_24px_-8px_rgba(255,122,89,0.6)]"
    style="width: {size}px; height: {size}px; background: linear-gradient(145deg, #ff9a7b 0%, #ff7a59 45%, #5ac8e8 130%);"
  >
    <svg viewBox="0 0 32 32" width={size} height={size} fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="lg-{uid}" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stop-color="#fff5ec" />
          <stop offset="1" stop-color="#ffffff" stop-opacity="0.85" />
        </linearGradient>
      </defs>
      <path d="M10 22 L16 11 L22 22 Z" stroke="url(#lg-{uid})" stroke-width="2" stroke-linejoin="round" fill="rgba(255,255,255,0.08)" />
      <circle cx="16" cy="11" r="2.6" fill="#0b0f17" stroke="#fff" stroke-width="1.6" />
      <circle cx="10" cy="22" r="2.6" fill="#0b0f17" stroke="#fff" stroke-width="1.6" />
      <circle cx="22" cy="22" r="2.6" fill="#0b0f17" stroke="#fff" stroke-width="1.6" />
    </svg>
  </span>
  {#if withText}
    <span class="font-display font-bold tracking-tight text-fg {textClass}">cpmesh</span>
  {/if}
</span>
