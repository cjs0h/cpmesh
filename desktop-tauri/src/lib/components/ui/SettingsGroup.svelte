<script lang="ts">
	import type { Snippet } from 'svelte';

	/** A titled group of settings rows, separated by hairlines. */
	interface Props {
		title?: string;
		description?: string;
		id?: string;
		tone?: 'default' | 'danger';
		children: Snippet;
	}

	let { title, description, id, tone = 'default', children }: Props = $props();
</script>

<section {id} class="scroll-mt-6">
	{#if title}
		<div class="mb-2 px-1">
			<h2 class="text-[13px] font-semibold {tone === 'danger' ? 'text-danger-fg' : 'text-fg'}">{title}</h2>
			{#if description}<p class="mt-0.5 text-xs text-muted">{description}</p>{/if}
		</div>
	{/if}
	<div
		class="divide-y divide-border overflow-hidden rounded-xl border bg-surface {tone === 'danger' ? 'border-danger-line' : 'border-border'}"
	>
		{@render children()}
	</div>
</section>
