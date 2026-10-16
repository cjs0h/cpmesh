<script lang="ts">
	import { getAppStateValue } from '#lib/store.svelte.js';
	import Overview from '#lib/components/Overview.svelte';
	import SetupWizard from '#lib/components/SetupWizard.svelte';

	const appState = $derived(getAppStateValue());
</script>

<svelte:head>
	<title>cpmesh</title>
</svelte:head>

{#if appState === 'not_configured'}
	<SetupWizard />
{:else}
	<Overview />
{/if}
