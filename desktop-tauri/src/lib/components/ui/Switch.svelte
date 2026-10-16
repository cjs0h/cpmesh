<script lang="ts">
	import type { HTMLInputAttributes } from 'svelte/elements';

	interface Props extends Omit<HTMLInputAttributes, 'type' | 'checked'> {
		checked?: boolean;
		/** Accessible name when the switch has no visible label next to it. */
		label: string;
		class?: string;
	}

	let { checked = $bindable(false), label, class: className = '', ...rest }: Props = $props();
</script>

<span class="relative inline-flex h-5 w-9 shrink-0 items-center {className}">
	<input type="checkbox" role="switch" aria-label={label} bind:checked class="peer absolute inset-0 z-10 m-0 cursor-pointer opacity-0 disabled:cursor-not-allowed" {...rest} />
	<span
		class="absolute inset-0 rounded-full bg-dim transition-colors duration-150 peer-checked:bg-ink peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-ink peer-disabled:opacity-50"
	></span>
	<span
		class="pointer-events-none absolute left-0.5 h-4 w-4 rounded-full bg-white shadow-sm transition-transform duration-200 ease-[var(--ease-out-expo)] peer-checked:translate-x-4 dark:peer-checked:bg-[#0a0a0a]"
	></span>
</span>
