<script lang="ts">
	import { onDestroy } from 'svelte';
	import { copyText } from '#lib/api.js';
	import { toast } from '#lib/toast.svelte.js';
	import { errorMessage } from '#lib/ui.js';
	import Button from './Button.svelte';

	/** Copies `text` (which cpmesh then syncs like any copy) and confirms it in place. */
	interface Props {
		text: string;
		/** Accessible name, e.g. "Copy the device ID". */
		label: string;
	}

	let { text, label }: Props = $props();

	let copied = $state(false);
	let timer: ReturnType<typeof setTimeout> | undefined;

	async function copy() {
		try {
			await copyText(text);
			copied = true;
			clearTimeout(timer);
			timer = setTimeout(() => (copied = false), 1600);
		} catch (e) {
			toast.error('Couldn’t copy to the clipboard', errorMessage(e));
		}
	}

	onDestroy(() => clearTimeout(timer));
</script>

<Button size="sm" icon={copied ? 'check' : 'copy'} aria-label={copied ? 'Copied' : label} onclick={copy}>{copied ? 'Copied' : 'Copy'}</Button>
