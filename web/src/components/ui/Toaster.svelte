<script lang="ts">
  import { dismissToast, toastState, type ToastKind } from '../../lib/stores/toast.svelte';
  import Icon from '../Icon.svelte';

  const styles: Record<ToastKind, { icon: string; fill: string }> = {
    success: { icon: 'check-circle', fill: 'bg-mint' },
    error: { icon: 'alert-circle', fill: 'bg-rose' },
    warning: { icon: 'alert-triangle', fill: 'bg-yellow' },
    info: { icon: 'info', fill: 'bg-cyan' },
  };
</script>

<div class="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[min(92vw,380px)] flex-col gap-3" aria-live="polite" aria-atomic="false">
  {#each toastState.items as t (t.id)}
    <div
      class="pointer-events-auto relative flex items-stretch overflow-hidden rounded-md border-2 border-ink bg-surface shadow-lg animate-[toast-in_0.3s_var(--ease-out-expo)]"
      role={t.kind === 'error' ? 'alert' : 'status'}
    >
      <span class="flex w-11 shrink-0 items-center justify-center border-r-2 border-ink text-ink {styles[t.kind].fill}"><Icon name={styles[t.kind].icon} size={18} strokeWidth={2.5} /></span>
      <div class="min-w-0 flex-1 px-3.5 py-3">
        <p class="font-head text-[13px] text-ink">{t.title}</p>
        {#if t.description}<p class="mt-0.5 text-[13px] leading-snug text-muted">{t.description}</p>{/if}
      </div>
      <button type="button" class="shrink-0 px-3 text-ink/60 transition-colors hover:text-ink" aria-label="Dismiss notification" onclick={() => dismissToast(t.id)}>
        <Icon name="x" size={14} strokeWidth={2.5} />
      </button>
    </div>
  {/each}
</div>
