<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		title: string;
		description?: string;
		actions?: Snippet;
	}

	let { title, description, actions }: Props = $props();
</script>

<header class="mb-6 flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
	<div class="min-w-0">
		<h1 class="text-lg font-semibold tracking-tight text-fg">{title}</h1>
		{#if description}<p class="mt-0.5 max-w-[60ch] text-[13px] text-muted">{description}</p>{/if}
	</div>
	{#if actions}
		<div class="flex shrink-0 flex-wrap items-center gap-2">{@render actions()}</div>
	{/if}
</header>
