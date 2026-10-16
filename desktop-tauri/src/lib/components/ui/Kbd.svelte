<script lang="ts">
	import { shortcutKeys } from '#lib/ui.js';

	/** Keyboard shortcut, with modifiers spelled for the current platform ('mod' is ⌘ or Ctrl). */
	let { keys, class: className = '' }: { keys: string[]; class?: string } = $props();
	const labels = $derived(shortcutKeys(keys));
</script>

<span class="inline-flex items-center gap-0.5 {className}">
	{#each labels as key, i (i)}
		<kbd
			class="inline-flex h-5 min-w-5 items-center justify-center rounded border border-border bg-surface px-1 text-[11px] leading-none font-medium text-muted shadow-[0_1px_0_var(--color-border)]"
			>{key}</kbd
		>
	{/each}
</span>
