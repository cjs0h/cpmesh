<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLButtonAttributes } from 'svelte/elements';
	import Icon from './Icon.svelte';

	type Variant = 'primary' | 'accent' | 'secondary' | 'ghost' | 'danger' | 'danger-soft' | 'link';
	type Size = 'xs' | 'sm' | 'md' | 'lg' | 'icon' | 'icon-sm';

	interface Props extends HTMLButtonAttributes {
		variant?: Variant;
		size?: Size;
		loading?: boolean;
		/** Render as an anchor instead of a button. */
		href?: string;
		icon?: string;
		iconRight?: string;
		class?: string;
		children?: Snippet;
	}

	let {
		variant = 'secondary',
		size = 'md',
		loading = false,
		href,
		icon,
		iconRight,
		class: className = '',
		children,
		disabled,
		type = 'button',
		...rest
	}: Props = $props();

	const base =
		'inline-flex items-center justify-center gap-2 whitespace-nowrap select-none rounded-md font-medium ' +
		'transition-[background-color,border-color,color,box-shadow,transform] duration-150 active:translate-y-px ' +
		'focus-visible:outline-2 focus-visible:outline-ink focus-visible:outline-offset-2 ' +
		'disabled:opacity-50 disabled:pointer-events-none aria-disabled:opacity-50 aria-disabled:pointer-events-none';

	const variants: Record<Variant, string> = {
		primary: 'bg-ink text-on-ink hover:bg-ink-hover',
		accent: 'bg-accent text-white hover:bg-accent-hover',
		secondary: 'border border-border bg-surface text-fg shadow-xs hover:border-border-strong hover:bg-bg-deep',
		ghost: 'bg-transparent text-muted hover:bg-surface-2 hover:text-fg',
		danger: 'bg-danger text-white hover:bg-danger-hover',
		'danger-soft': 'border border-danger-line bg-danger-soft text-danger-fg hover:border-danger',
		link: 'text-fg underline underline-offset-4 decoration-border-strong hover:decoration-fg active:translate-y-0',
	};

	const sizes: Record<Size, string> = {
		xs: 'h-7 px-2.5 text-xs',
		sm: 'h-8 px-3 text-[13px]',
		md: 'h-9 px-3.5 text-[13px]',
		lg: 'h-10 px-4 text-sm',
		icon: 'h-9 w-9 p-0',
		'icon-sm': 'h-7 w-7 p-0',
	};

	const iconSize = $derived(size === 'xs' || size === 'icon-sm' ? 14 : 15);
	const classes = $derived([base, variants[variant], variant === 'link' ? '' : sizes[size], className].filter(Boolean).join(' '));
	const isDisabled = $derived(Boolean(disabled) || loading);
</script>

{#snippet content()}
	{#if loading}
		<Icon name="loader" size={iconSize} class="animate-[spin_0.8s_linear_infinite]" />
	{:else if icon}
		<Icon name={icon} size={iconSize} />
	{/if}
	{#if children}{@render children()}{/if}
	{#if iconRight && !loading}
		<Icon name={iconRight} size={iconSize} />
	{/if}
{/snippet}

{#if href}
	<a
		{href}
		class={classes}
		aria-disabled={isDisabled || undefined}
		tabindex={isDisabled ? -1 : undefined}
		{...rest as Record<string, unknown>}
	>
		{@render content()}
	</a>
{:else}
	<button {type} class={classes} disabled={isDisabled} aria-busy={loading || undefined} {...rest}>
		{@render content()}
	</button>
{/if}
