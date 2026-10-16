<script lang="ts">
	import type { Snippet } from 'svelte';

	type Tone = 'neutral' | 'success' | 'warning' | 'danger' | 'accent' | 'ink';

	interface Props {
		tone?: Tone;
		dot?: boolean;
		live?: boolean;
		class?: string;
		children: Snippet;
	}

	let { tone = 'neutral', dot = false, live = false, class: className = '', children }: Props = $props();

	const tones: Record<Tone, string> = {
		neutral: 'border-border bg-surface text-muted',
		success: 'border-success-line bg-success-soft text-success-fg',
		warning: 'border-warning-line bg-warning-soft text-warning-fg',
		danger: 'border-danger-line bg-danger-soft text-danger-fg',
		accent: 'border-accent/30 bg-accent-soft text-accent',
		ink: 'border-ink bg-ink text-on-ink',
	};
</script>

<span class="inline-flex items-center gap-1.5 rounded-full border px-2 py-px text-[11px] font-medium whitespace-nowrap {tones[tone]} {className}">
	{#if dot}<span class="status-dot" data-live={live}></span>{/if}
	{@render children()}
</span>
