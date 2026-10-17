<script lang="ts">
	import { onMount } from 'svelte';
	import { getGlobalShortcut, setGlobalShortcut, type ShortcutStatus } from '#lib/api.js';
	import { acceleratorText } from '#lib/shortcuts.js';
	import { toast } from '#lib/toast.svelte.js';
	import { errorMessage } from '#lib/ui.js';
	import Button from './ui/Button.svelte';
	import CopyButton from './ui/CopyButton.svelte';
	import SettingRow from './ui/SettingRow.svelte';
	import ShortcutRecorder from './ui/ShortcutRecorder.svelte';

	// Settings rows for the shortcut that shows cpmesh from any app (desktop only)

	let status = $state<ShortcutStatus | null>(null);
	let loadError = $state('');
	let saving = $state(false);
	let recording = $state(false);
	/** Why the combination just pressed can't be used. */
	let hint = $state('');
	/** Why the last change didn't go through. */
	let failure = $state('');

	const description = $derived(
		recording
			? 'Press the keys you want to use. Esc cancels.'
			: status && !status.shortcut
				? 'Turned off. Set a shortcut to bring cpmesh forward from any app.'
				: 'Brings cpmesh forward from any app.',
	);

	async function load() {
		loadError = '';
		try {
			status = await getGlobalShortcut();
		} catch (e) {
			loadError = errorMessage(e);
		}
	}

	async function change(shortcut: string, done: string) {
		if (saving || !status) return;
		const retry = shortcut === status.shortcut;
		saving = true;
		hint = '';
		failure = '';
		try {
			status = await setGlobalShortcut(shortcut);
			toast.success(done, status.shortcut ? `Press ${acceleratorText(status.shortcut)} in any app to bring cpmesh forward.` : undefined);
		} catch (e) {
			const reason = errorMessage(e);
			failure = retry ? `Still not working. ${reason}` : shortcut ? `Couldn’t switch to ${acceleratorText(shortcut)}. ${reason}` : reason;
		} finally {
			saving = false;
		}
	}

	function clearMessages() {
		hint = '';
		failure = '';
	}

	onMount(load);
</script>

<SettingRow label="Show cpmesh from anywhere">
	{#snippet control()}
		{#if status && status.shortcut !== status.default_shortcut}
			<Button
				size="sm"
				variant="ghost"
				disabled={saving}
				title="Go back to {acceleratorText(status.default_shortcut)}"
				onclick={() => status && change(status.default_shortcut, 'Shortcut reset')}>Reset</Button
			>
		{/if}
		<ShortcutRecorder
			label="Shortcut to show cpmesh"
			value={status?.shortcut ?? ''}
			disabled={!status}
			busy={saving || (!status && !loadError)}
			bind:recording
			onstart={clearMessages}
			onrecord={(accelerator) => change(accelerator, 'Shortcut changed')}
			oninvalid={(reason) => (hint = reason)}
		/>
		{#if status?.shortcut}
			<Button
				size="icon-sm"
				variant="ghost"
				icon="x"
				aria-label="Turn off the shortcut"
				title="Turn off"
				disabled={saving}
				onclick={() => change('', 'Shortcut turned off')}
			/>
		{/if}
	{/snippet}
	<p class="mt-0.5 text-xs leading-relaxed text-muted">{description}</p>
	<div aria-live="polite">
		{#if recording && hint}
			<p class="mt-1 text-xs leading-relaxed text-warning-fg">{hint}</p>
		{:else if loadError}
			<p class="mt-1 text-xs leading-relaxed text-danger-fg">Couldn’t load the shortcut. {loadError}</p>
			<Button size="xs" icon="refresh" class="mt-2" onclick={load}>Try again</Button>
		{:else if failure}
			<p class="mt-1 text-xs leading-relaxed text-danger-fg">{failure}</p>
		{:else if status?.error}
			<p class="mt-1 text-xs leading-relaxed text-warning-fg">Not working right now. {status.error}</p>
		{/if}
		{#if status?.error && !recording}
			<Button size="xs" icon="refresh" class="mt-2" loading={saving} onclick={() => status && change(status.shortcut, 'Shortcut is working')}>
				Try again
			</Button>
		{/if}
	</div>
</SettingRow>

{#if status?.launch_command}
	<SettingRow
		label="Shortcut not responding?"
		description="Wayland desktops may not pass shortcuts on to apps. If pressing it does nothing, add a custom shortcut in your desktop’s keyboard settings that runs this command:"
	>
		<code class="mt-2 block rounded-md border border-border bg-bg-deep px-2.5 py-1.5 font-mono text-xs break-all text-fg"
			>{status.launch_command}</code
		>
		{#snippet control()}<CopyButton text={status?.launch_command ?? ''} label="Copy the command" />{/snippet}
	</SettingRow>
{/if}
