<script lang="ts">
	import type { Snippet } from 'svelte';
	import Icon from './Icon.svelte';

	/** Modal dialog on the native <dialog> element: focus trap, Escape and top layer for free. */
	interface Props {
		open?: boolean;
		title: string;
		description?: string;
		size?: 'sm' | 'md';
		/** Blocks closing by Escape, backdrop or the close button (e.g. while a request runs). */
		locked?: boolean;
		onclose?: () => void;
		footer?: Snippet;
		children?: Snippet;
	}

	let { open = $bindable(false), title, description, size = 'md', locked = false, onclose, footer, children }: Props = $props();

	let dialog = $state<HTMLDialogElement | null>(null);
	const uid = $props.id();

	$effect(() => {
		const el = dialog;
		if (!el) return;
		if (open && !el.open) el.showModal();
		else if (!open && el.open) el.close();
	});

	function requestClose() {
		if (locked) return;
		open = false;
	}

	// Fired after the element closed, however that happened
	function handleClose() {
		if (open) open = false;
		onclose?.();
	}

	function handleCancel(event: Event) {
		event.preventDefault();
		requestClose();
	}

	function onBackdropClick(event: MouseEvent) {
		if (event.target === dialog) requestClose();
	}
</script>

<dialog
	bind:this={dialog}
	class="m-auto w-[calc(100%-2rem)] {size === 'sm' ? 'max-w-[400px]' : 'max-w-[520px]'} rounded-xl border border-border bg-surface p-0 text-fg shadow-pop backdrop:bg-black/40 backdrop:backdrop-blur-[1px] open:animate-[pop-in_0.18s_var(--ease-out-expo)]"
	aria-labelledby="dialog-title-{uid}"
	aria-describedby={description ? `dialog-desc-${uid}` : undefined}
	onclose={handleClose}
	oncancel={handleCancel}
	onclick={onBackdropClick}
>
	<div class="flex items-start justify-between gap-4 px-5 pt-5 pb-1">
		<div class="min-w-0">
			<h2 id="dialog-title-{uid}" class="text-[15px] font-semibold text-fg">{title}</h2>
			{#if description}
				<p id="dialog-desc-{uid}" class="mt-1 text-[13px] leading-relaxed text-muted">{description}</p>
			{/if}
		</div>
		<button
			type="button"
			class="-mt-1 -mr-1.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-dim transition-colors hover:bg-surface-2 hover:text-fg disabled:opacity-40"
			aria-label="Close dialog"
			disabled={locked}
			onclick={requestClose}
		>
			<Icon name="x" size={15} />
		</button>
	</div>

	{#if children}
		<div class="max-h-[60vh] overflow-y-auto px-5 py-3">
			{@render children()}
		</div>
	{/if}

	{#if footer}
		<div class="flex flex-wrap items-center justify-end gap-2 px-5 pt-2 pb-5">
			{@render footer()}
		</div>
	{/if}
</dialog>
