<script lang="ts">
	import type { Snippet } from 'svelte';
	import type { HTMLInputAttributes } from 'svelte/elements';
	import Icon from './Icon.svelte';

	interface Props extends Omit<HTMLInputAttributes, 'value' | 'type'> {
		label?: string;
		hint?: string;
		error?: string;
		icon?: string;
		type?: 'text' | 'email' | 'password' | 'tel' | 'url' | 'search';
		value?: string | null;
		optional?: boolean;
		class?: string;
		inputClass?: string;
		/** Element rendered inside the input, on the right (e.g. a clear button or a key hint). */
		trailing?: Snippet;
		input?: HTMLInputElement | null;
	}

	let {
		label,
		hint,
		error,
		icon,
		type = 'text',
		value = $bindable(''),
		optional = false,
		class: className = '',
		inputClass = '',
		trailing,
		input = $bindable(null),
		id,
		...rest
	}: Props = $props();

	const uid = $props.id();
	const inputId = $derived(id ?? `field-${uid}`);
	let revealed = $state(false);
	const effectiveType = $derived(type === 'password' && revealed ? 'text' : type);
	const describedBy = $derived(error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined);
	const hasTrailing = $derived(type === 'password' || Boolean(trailing));
</script>

<div class="flex flex-col gap-1.5 {className}">
	{#if label}
		<label for={inputId} class="flex items-center gap-1 text-[13px] font-medium text-fg">
			{label}
			{#if optional}<span class="ml-auto text-xs font-normal text-dim">Optional</span>{/if}
		</label>
	{/if}

	<div class="relative">
		{#if icon}
			<span class="pointer-events-none absolute inset-y-0 left-3 flex items-center text-dim">
				<Icon name={icon} size={15} />
			</span>
		{/if}

		<input
			bind:this={input}
			id={inputId}
			type={effectiveType}
			bind:value
			aria-invalid={error ? 'true' : undefined}
			aria-describedby={describedBy}
			class="h-9 w-full rounded-md border bg-surface text-[13px] text-fg shadow-xs outline-none transition-[border-color,box-shadow] duration-150 placeholder:text-dim
				focus:border-ink focus:shadow-[0_0_0_3px_color-mix(in_srgb,var(--color-ink)_10%,transparent)]
				disabled:cursor-not-allowed disabled:bg-surface-2 disabled:opacity-70
				{icon ? 'pl-9' : 'pl-3'} {hasTrailing ? 'pr-10' : 'pr-3'}
				{error ? 'border-danger focus:border-danger' : 'border-border hover:border-border-strong'}
				{inputClass}"
			{...rest}
		/>

		{#if type === 'password'}
			<button
				type="button"
				class="absolute inset-y-0 right-0 flex w-10 items-center justify-center rounded-r-md text-dim transition-colors hover:text-fg"
				aria-label={revealed ? 'Hide password' : 'Show password'}
				aria-pressed={revealed}
				onclick={() => (revealed = !revealed)}
			>
				<Icon name={revealed ? 'eye-off' : 'eye'} size={15} />
			</button>
		{:else if trailing}
			<span class="absolute inset-y-0 right-0 flex items-center pr-2">{@render trailing()}</span>
		{/if}
	</div>

	{#if error}
		<p id="{inputId}-error" class="text-xs text-danger-fg" role="alert">{error}</p>
	{:else if hint}
		<p id="{inputId}-hint" class="text-xs text-muted">{hint}</p>
	{/if}
</div>
