<script lang="ts" generics="T extends string">
	import Icon from './Icon.svelte';

	/** A row of mutually exclusive options (radio group styled as a segmented control). */
	interface Option {
		value: T;
		label: string;
		icon?: string;
	}

	interface Props {
		options: Option[];
		value: T;
		label: string;
		size?: 'sm' | 'md';
		stretch?: boolean;
		onchange?: (value: T) => void;
		class?: string;
	}

	let { options, value = $bindable(), label, size = 'md', stretch = false, onchange, class: className = '' }: Props = $props();

	function select(next: T) {
		if (next === value) return;
		value = next;
		onchange?.(next);
	}

	// Arrow keys move the selection, like a native radio group
	function onkeydown(event: KeyboardEvent) {
		const index = options.findIndex((o) => o.value === value);
		let next = index;
		if (event.key === 'ArrowRight' || event.key === 'ArrowDown') next = (index + 1) % options.length;
		else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') next = (index - 1 + options.length) % options.length;
		else return;
		event.preventDefault();
		select(options[next].value);
		const group = event.currentTarget as HTMLElement;
		(group.querySelectorAll<HTMLButtonElement>('[role="radio"]')[next])?.focus();
	}
</script>

<div
	role="radiogroup"
	aria-label={label}
	tabindex="-1"
	class="inline-flex items-center gap-0.5 rounded-lg border border-border bg-surface-2 p-0.5 {stretch ? 'flex w-full' : ''} {className}"
	{onkeydown}
>
	{#each options as option (option.value)}
		{@const active = option.value === value}
		<button
			type="button"
			role="radio"
			aria-checked={active}
			tabindex={active ? 0 : -1}
			class="inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-[background-color,color,box-shadow] duration-150
				{size === 'sm' ? 'h-6 px-2 text-xs' : 'h-7 px-3 text-[13px]'}
				{stretch ? 'flex-1' : ''}
				{active ? 'bg-surface text-fg shadow-sm dark:bg-surface-3' : 'text-muted hover:text-fg'}"
			onclick={() => select(option.value)}
		>
			{#if option.icon}<Icon name={option.icon} size={13} />{/if}
			{option.label}
		</button>
	{/each}
</div>
