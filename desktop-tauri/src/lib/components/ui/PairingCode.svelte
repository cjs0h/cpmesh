<script lang="ts">
	import Fingerprint from './Fingerprint.svelte';

	/**
	 * The committed short authentication string both devices show while pairing,
	 * with the full 64-character code available for a stronger manual check.
	 */
	let {
		code,
		fullCode,
		label = 'Pairing code',
		class: className = '',
	}: { code: string; fullCode?: string; label?: string; class?: string } = $props();
</script>

<div class={className}>
	<div
		role="group"
		aria-label={label}
		class="rounded-lg border border-border bg-bg-deep px-4 py-4 text-center font-mono text-[28px] font-semibold tracking-[0.3em] text-fg tabular-nums select-all"
	>
		{code}
	</div>
	{#if fullCode}
		<details class="mt-3 text-xs text-muted">
			<summary class="cursor-pointer select-none font-medium text-fg">Full 64-character code (stronger manual check)</summary>
			<Fingerprint class="mt-2" value={fullCode} label="Full pairing code" />
		</details>
	{/if}
</div>
