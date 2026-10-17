<script lang="ts">
	import Icon from './Icon.svelte';
	import Kbd from './Kbd.svelte';
	import { acceleratorKeys, acceleratorText, heldModifierKeys, recordShortcut } from '#lib/shortcuts.js';

	/**
	 * Shows a global shortcut and records a new one: activate it, then press the keys.
	 * Esc cancels; Tab moves on as usual.
	 */
	interface Props {
		/** Accelerator such as "CmdOrCtrl+Shift+Space"; empty when there is none. */
		value: string;
		/** Accessible name, e.g. "Shortcut to show cpmesh". */
		label: string;
		/** Whether it's waiting for keys. */
		recording?: boolean;
		disabled?: boolean;
		/** Shows a spinner, e.g. while a new shortcut is saved. */
		busy?: boolean;
		id?: string;
		onstart?: () => void;
		/** Called with a combination that can be used. */
		onrecord: (accelerator: string) => void;
		/** Called when a combination that can't be used was pressed, with the reason. */
		oninvalid?: (reason: string) => void;
	}

	let { value, label, recording = $bindable(false), disabled = false, busy = false, id, onstart, onrecord, oninvalid }: Props = $props();

	/** Keys held so far while recording. */
	let held = $state<string[]>([]);
	const inactive = $derived(disabled || busy);

	function start() {
		if (inactive) return;
		held = [];
		recording = true;
		onstart?.();
	}

	function stop() {
		recording = false;
		held = [];
	}

	function onkeydown(event: KeyboardEvent) {
		if (!recording) {
			if (event.key === 'Enter' || event.key === ' ') {
				event.preventDefault();
				start();
			}
			return;
		}
		const plain = !event.ctrlKey && !event.altKey && !event.metaKey;
		// Tab still moves focus on, which ends recording
		if (event.key === 'Tab' && plain) return;
		// Keep the keys from the window's own shortcuts (⌘1…4 and the like)
		event.preventDefault();
		event.stopPropagation();
		if (event.repeat) return;
		if (event.key === 'Escape' && plain && !event.shiftKey) {
			stop();
			return;
		}
		const result = recordShortcut(event);
		if (result.kind === 'shortcut') {
			stop();
			onrecord(result.accelerator);
			return;
		}
		held = result.keys;
		if (result.kind === 'invalid') oninvalid?.(result.reason);
	}

	function onkeyup(event: KeyboardEvent) {
		if (!recording) return;
		event.preventDefault();
		event.stopPropagation();
		held = heldModifierKeys(event);
	}
</script>

<div
	{id}
	role="button"
	tabindex={disabled ? -1 : 0}
	aria-label="{label}: {recording ? 'press the new shortcut' : value ? acceleratorText(value) : 'not set'}"
	aria-pressed={recording}
	aria-disabled={inactive || undefined}
	aria-busy={busy || undefined}
	class="inline-flex h-8 min-w-32 cursor-pointer items-center justify-center gap-1.5 rounded-md border px-2.5 text-xs whitespace-nowrap shadow-xs transition-colors duration-150 outline-none select-none focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink aria-disabled:pointer-events-none aria-disabled:opacity-50
		{recording ? 'border-ink bg-bg-deep' : 'border-border bg-surface hover:border-border-strong'}"
	onclick={() => (recording ? stop() : start())}
	onblur={stop}
	{onkeydown}
	{onkeyup}
>
	{#if busy}
		<Icon name="loader" size={14} class="animate-[spin_0.8s_linear_infinite] text-muted" />
	{:else if recording}
		{#if held.length > 0}<Kbd keys={held} />{:else}<span class="text-muted">Press keys…</span>{/if}
	{:else if value}
		<Kbd keys={acceleratorKeys(value)} />
	{:else}
		<span class="text-dim">Not set</span>
	{/if}
</div>
