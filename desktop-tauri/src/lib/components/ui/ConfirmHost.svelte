<script lang="ts">
	import { confirmState, settleConfirm } from '#lib/confirm.svelte.js';
	import Button from './Button.svelte';
	import Dialog from './Dialog.svelte';

	const current = $derived(confirmState.current);
</script>

<!-- Escape, the backdrop and the close button settle as "cancel"; settling twice is a no-op -->
<Dialog
	open={current !== null}
	size="sm"
	title={current?.title ?? ''}
	description={current?.description}
	onclose={() => settleConfirm(false)}
>
	{#snippet footer()}
		<Button variant="ghost" onclick={() => settleConfirm(false)}>{current?.cancelLabel ?? 'Cancel'}</Button>
		<Button variant={current?.tone === 'danger' ? 'danger' : 'primary'} onclick={() => settleConfirm(true)}>
			{current?.confirmLabel ?? 'Confirm'}
		</Button>
	{/snippet}
</Dialog>
