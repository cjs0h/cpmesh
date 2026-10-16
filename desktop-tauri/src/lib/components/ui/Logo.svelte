<script lang="ts">
	/** Brand mark: three mesh nodes on a near-black tile, identical in both themes. */
	let { size = 28, withText = false, class: className = '' }: { size?: number; withText?: boolean; class?: string } = $props();
</script>

<span class="inline-flex items-center gap-2 {className}">
	<span
		class="inline-flex shrink-0 items-center justify-center rounded-[22%] bg-[#0a0a0a] dark:ring-1 dark:ring-white/10"
		style="width: {size}px; height: {size}px;"
	>
		<svg viewBox="0 0 32 32" width={size} height={size} fill="none" aria-hidden="true">
			<path d="M10 22 L16 11 L22 22 Z" stroke="#ffffff" stroke-width="1.8" stroke-linejoin="round" />
			<circle cx="16" cy="11" r="2.6" fill="#0a0a0a" stroke="#ffffff" stroke-width="1.8" />
			<circle cx="10" cy="22" r="2.6" fill="#0a0a0a" stroke="#ffffff" stroke-width="1.8" />
			<circle cx="22" cy="22" r="2.6" fill="#ff5c38" stroke="#ffffff" stroke-width="1.8" />
		</svg>
	</span>
	{#if withText}
		<span class="text-[15px] font-semibold tracking-tight text-fg">cpmesh</span>
	{/if}
</span>
