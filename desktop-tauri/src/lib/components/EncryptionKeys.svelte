<script lang="ts">
	import { openKeyRecovery, recovery } from '#lib/recovery.svelte.js';
	import Button from './ui/Button.svelte';
	import SettingRow from './ui/SettingRow.svelte';
	import SettingsGroup from './ui/SettingsGroup.svelte';

	/** Settings → Encryption keys; the dialog itself lives in the layout. */
</script>

<SettingsGroup title="Encryption keys">
	<SettingRow
		label={recovery.keyProblem ? 'This device is missing your encryption key' : 'Restore keys'}
		description={recovery.keyProblem
			? 'Sync is paused. Get the key from another device, restore it from a backup, or start new keys as a last resort.'
			: 'Bring back keys from a backup on this computer or from a folder, to read clips synced before this device had them.'}
	>
		{#snippet control()}
			<Button size="sm" variant={recovery.keyProblem ? 'primary' : 'secondary'} icon="key" onclick={openKeyRecovery}>
				{recovery.keyProblem ? 'Recover keys…' : 'Restore keys…'}
			</Button>
		{/snippet}
	</SettingRow>
</SettingsGroup>
