<script lang="ts">
	import type { Snippet } from 'svelte';
	import Icon from './Icon.svelte';

	type Tone = 'info' | 'success' | 'warning' | 'danger';

	interface Props {
		tone?: Tone;
		title?: string;
		icon?: string;
		ondismiss?: () => void;
		class?: string;
		actions?: Snippet;
		children?: Snippet;
	}

	let { tone = 'info', title, icon, ondismiss, class: className = '', actions, children }: Props = $props();

	const styles: Record<Tone, { box: string; icon: string; iconColor: string }> = {
		info: { box: 'border-border bg-bg-deep text-fg', icon: 'info', iconColor: 'text-muted' },
		success: { box: 'border-success-line bg-success-soft text-fg', icon: 'check-circle', iconColor: 'text-success' },
		warning: { box: 'border-warning-line bg-warning-soft text-fg', icon: 'alert-triangle', iconColor: 'text-warning' },
		danger: { box: 'border-danger-line bg-danger-soft text-fg', icon: 'alert-circle', iconColor: 'text-danger' },
	};
</script>

<div
	class="flex items-start gap-3 rounded-lg border px-3.5 py-3 text-[13px] leading-relaxed {styles[tone].box} {className}"
	role={tone === 'danger' || tone === 'warning' ? 'alert' : 'status'}
>
	<span class="mt-0.5 shrink-0 {styles[tone].iconColor}"><Icon name={icon ?? styles[tone].icon} size={15} /></span>
	<div class="min-w-0 flex-1">
		{#if title}<p class="font-medium">{title}</p>{/if}
		{#if children}<div class="text-muted {title ? 'mt-0.5' : ''} [overflow-wrap:anywhere]">{@render children()}</div>{/if}
		{#if actions}<div class="mt-2.5 flex flex-wrap items-center gap-2">{@render actions()}</div>{/if}
	</div>
	{#if ondismiss}
		<button
			type="button"
			class="-mt-1 -mr-1.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-dim transition-colors hover:bg-black/5 hover:text-fg dark:hover:bg-white/10"
			aria-label="Dismiss"
			onclick={ondismiss}
		>
			<Icon name="x" size={14} />
		</button>
	{/if}
</div>
