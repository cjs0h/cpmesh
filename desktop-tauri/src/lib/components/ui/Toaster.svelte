<script lang="ts">
	import { dismissToast, toastState, type ToastKind } from '#lib/toast.svelte.js';
	import Icon from './Icon.svelte';

	const styles: Record<ToastKind, { icon: string; color: string }> = {
		success: { icon: 'check-circle', color: 'text-success' },
		error: { icon: 'alert-circle', color: 'text-danger' },
		warning: { icon: 'alert-triangle', color: 'text-warning' },
		info: { icon: 'info', color: 'text-muted' },
	};
</script>

<div
	class="pointer-events-none fixed right-4 bottom-4 z-[100] flex w-[min(92vw,340px)] flex-col gap-2 max-sm:bottom-[calc(4.5rem+env(safe-area-inset-bottom))]"
	aria-live="polite"
>
	{#each toastState.items as t (t.id)}
		<div
			class="pointer-events-auto flex items-start gap-3 rounded-lg border border-border bg-surface px-3.5 py-3 shadow-lg animate-[rise-in_0.2s_var(--ease-out-expo)]"
			role={t.kind === 'error' ? 'alert' : 'status'}
		>
			<span class="mt-0.5 shrink-0 {styles[t.kind].color}"><Icon name={styles[t.kind].icon} size={15} /></span>
			<div class="min-w-0 flex-1">
				<p class="text-[13px] font-medium text-fg">{t.title}</p>
				{#if t.description}<p class="mt-0.5 text-[12px] leading-snug text-muted [overflow-wrap:anywhere]">{t.description}</p>{/if}
			</div>
			<button
				type="button"
				class="-mt-0.5 -mr-1 shrink-0 rounded p-1 text-dim transition-colors hover:text-fg"
				aria-label="Dismiss notification"
				onclick={() => dismissToast(t.id)}
			>
				<Icon name="x" size={13} />
			</button>
		</div>
	{/each}
</div>
