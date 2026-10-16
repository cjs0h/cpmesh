<script lang="ts">
	import { fingerprintGroups } from '#lib/ui.js';

	/**
	 * A full fingerprint laid out in groups of four so two people can compare it
	 * group by group. Every character is always shown.
	 */
	let { value, label, class: className = '' }: { value: string; label: string; class?: string } = $props();

	const groups = $derived(fingerprintGroups(value));
</script>

<div
	role="group"
	aria-label={label}
	class="grid grid-cols-4 gap-x-3 gap-y-1.5 rounded-lg border border-border bg-bg-deep px-4 py-3 font-mono text-[13px] font-medium tracking-[0.12em] text-fg tabular-nums select-all {className}"
>
	{#each groups as group, i (i)}
		<span class="text-center">{group}</span>
	{/each}
</div>
