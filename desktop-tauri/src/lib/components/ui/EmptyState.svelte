<script lang="ts">
	import type { Snippet } from 'svelte';
	import Icon from './Icon.svelte';

	interface Props {
		icon?: string;
		title: string;
		description?: string;
		class?: string;
		children?: Snippet;
	}

	let { icon = 'inbox', title, description, class: className = '', children }: Props = $props();
</script>

<div class="flex flex-col items-center px-6 py-12 text-center {className}">
	<div class="mb-4 flex h-11 w-11 items-center justify-center rounded-xl border border-border bg-surface text-muted shadow-xs">
		<Icon name={icon} size={19} strokeWidth={1.75} />
	</div>
	<p class="text-sm font-medium text-fg">{title}</p>
	{#if description}
		<p class="mt-1 max-w-[42ch] text-[13px] leading-relaxed text-muted">{description}</p>
	{/if}
	{#if children}
		<div class="mt-5 flex flex-wrap items-center justify-center gap-2">{@render children()}</div>
	{/if}
</div>
