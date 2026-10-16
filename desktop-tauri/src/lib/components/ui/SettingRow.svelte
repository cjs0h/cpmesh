<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		label: string;
		description?: string;
		/** Id of the control this row labels, so clicking the label focuses it. */
		for?: string;
		control?: Snippet;
		children?: Snippet;
	}

	let { label, description, for: htmlFor, control, children }: Props = $props();
</script>

<div class="flex min-h-14 items-center justify-between gap-6 px-4 py-3">
	<div class="min-w-0">
		{#if htmlFor}
			<label for={htmlFor} class="text-[13px] font-medium text-fg">{label}</label>
		{:else}
			<p class="text-[13px] font-medium text-fg">{label}</p>
		{/if}
		{#if description}<p class="mt-0.5 text-xs leading-relaxed text-muted">{description}</p>{/if}
		{#if children}{@render children()}{/if}
	</div>
	{#if control}
		<div class="flex shrink-0 items-center gap-2">{@render control()}</div>
	{/if}
</div>
