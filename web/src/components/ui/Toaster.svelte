<script lang="ts">
  import { dismissToast, toastState, type ToastKind } from '../../lib/stores/toast.svelte';
  import Icon from '../Icon.svelte';

  const styles: Record<ToastKind, { icon: string; tone: string; bar: string }> = {
    success: { icon: 'check-circle', tone: 'text-mint', bar: 'bg-mint' },
    error: { icon: 'alert-circle', tone: 'text-rose', bar: 'bg-rose' },
    warning: { icon: 'alert-triangle', tone: 'text-gold', bar: 'bg-gold' },
    info: { icon: 'info', tone: 'text-cyan', bar: 'bg-cyan' },
  };
</script>

<div class="pointer-events-none fixed bottom-4 right-4 z-[100] flex w-[min(92vw,380px)] flex-col gap-2" aria-live="polite" aria-atomic="false">
  {#each toastState.items as t (t.id)}
    <div
      class="pointer-events-auto relative flex items-start gap-3 overflow-hidden rounded-xl border border-border-strong bg-surface-2/95 px-4 py-3 shadow-pop backdrop-blur-md animate-[toast-in_0.3s_var(--ease-out-expo)]"
      role={t.kind === 'error' ? 'alert' : 'status'}
    >
      <span class="absolute inset-y-0 left-0 w-1 {styles[t.kind].bar}"></span>
      <span class="mt-0.5 shrink-0 {styles[t.kind].tone}"><Icon name={styles[t.kind].icon} size={17} /></span>
      <div class="min-w-0 flex-1">
        <p class="text-sm font-semibold text-fg">{t.title}</p>
        {#if t.description}<p class="mt-0.5 text-[13px] leading-snug text-muted">{t.description}</p>{/if}
      </div>
      <button type="button" class="-mr-1 -mt-0.5 shrink-0 rounded p-1 text-dim transition-colors hover:text-fg" aria-label="Dismiss notification" onclick={() => dismissToast(t.id)}>
        <Icon name="x" size={14} />
      </button>
    </div>
  {/each}
</div>
