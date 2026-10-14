<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from '../Icon.svelte';

  /** Modal dialog on the native <dialog> element (focus trap, Escape, top layer for free). */
  interface Props {
    open?: boolean;
    title: string;
    description?: string;
    size?: 'sm' | 'md' | 'lg';
    onclose?: () => void;
    footer?: Snippet;
    children: Snippet;
  }

  let { open = $bindable(false), title, description, size = 'md', onclose, footer, children }: Props = $props();

  let dialog = $state<HTMLDialogElement | null>(null);
  const uid = $props.id();

  $effect(() => {
    const el = dialog;
    if (!el) return;
    if (open && !el.open) el.showModal();
    else if (!open && el.open) el.close();
  });

  function handleClose() {
    open = false;
    onclose?.();
  }

  function onBackdropClick(e: MouseEvent) {
    if (e.target === dialog) handleClose();
  }

  const widths = { sm: 'max-w-sm', md: 'max-w-lg', lg: 'max-w-2xl' };
</script>

<dialog
  bind:this={dialog}
  class="m-auto w-[calc(100%-2rem)] {widths[size]} rounded-xl border border-border bg-surface p-0 text-fg shadow-pop backdrop:bg-black/30 backdrop:backdrop-blur-[2px] open:animate-[fade-in_0.15s_ease-out]"
  aria-labelledby="dialog-title-{uid}"
  aria-describedby={description ? `dialog-desc-${uid}` : undefined}
  onclose={handleClose}
  onclick={onBackdropClick}
>
  <div class="flex items-start justify-between gap-4 border-b border-border px-6 py-4">
    <div class="min-w-0">
      <h2 id="dialog-title-{uid}" class="text-base font-semibold text-fg">{title}</h2>
      {#if description}
        <p id="dialog-desc-{uid}" class="mt-0.5 text-[13px] text-muted">{description}</p>
      {/if}
    </div>
    <button type="button" class="-mr-2 -mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-dim transition-colors hover:bg-surface-2 hover:text-fg" aria-label="Close dialog" onclick={handleClose}>
      <Icon name="x" size={16} />
    </button>
  </div>

  <div class="max-h-[70vh] overflow-y-auto px-6 py-5">
    {@render children()}
  </div>

  {#if footer}
    <div class="flex flex-wrap items-center justify-end gap-2 border-t border-border bg-bg-deep px-6 py-4">
      {@render footer()}
    </div>
  {/if}
</dialog>
