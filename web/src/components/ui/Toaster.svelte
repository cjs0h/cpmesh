<script lang="ts">
  import { dismissToast, toastState, type ToastKind } from '../../lib/stores/toast.svelte';
  import Icon from '../Icon.svelte';

  const styles: Record<ToastKind, { icon: string; color: string }> = {
    success: { icon: 'check-circle', color: 'text-green-600' },
    error: { icon: 'alert-circle', color: 'text-red-600' },
    warning: { icon: 'alert-triangle', color: 'text-amber-600' },
    info: { icon: 'info', color: 'text-muted' },
  };
</script>

<div class="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[min(92vw,360px)] flex-col gap-2" aria-live="polite" aria-atomic="false">
  {#each toastState.items as t (t.id)}
    <div class="pointer-events-auto flex items-start gap-3 rounded-lg border border-border bg-surface px-4 py-3 shadow-lg animate-[toast-in_0.2s_ease-out]" role={t.kind === 'error' ? 'alert' : 'status'}>
      <span class="mt-0.5 shrink-0 {styles[t.kind].color}"><Icon name={styles[t.kind].icon} size={16} /></span>
      <div class="min-w-0 flex-1">
        <p class="text-sm font-medium text-fg">{t.title}</p>
        {#if t.description}<p class="mt-0.5 text-[13px] leading-snug text-muted">{t.description}</p>{/if}
      </div>
      <button type="button" class="-mr-1 -mt-0.5 shrink-0 rounded p-1 text-dim transition-colors hover:text-fg" aria-label="Dismiss notification" onclick={() => dismissToast(t.id)}>
        <Icon name="x" size={14} />
      </button>
    </div>
  {/each}
</div>
