<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from '../Icon.svelte';

  /**
   * Modal dialog built on the native <dialog> element: focus trapping, Escape
   * handling and the top layer all come for free.
   */
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
    // Clicks on the <dialog> itself (not its children) land on the backdrop.
    if (e.target === dialog) handleClose();
  }

  const widths = { sm: 'max-w-sm', md: 'max-w-lg', lg: 'max-w-2xl' };
</script>

<dialog
  bind:this={dialog}
  class="m-auto w-[calc(100%-2rem)] {widths[size]} rounded-2xl border border-border-strong bg-surface p-0 text-fg shadow-pop backdrop:bg-[rgba(4,9,17,0.7)] backdrop:backdrop-blur-sm open:animate-[scale-in_0.25s_var(--ease-out-expo)]"
  aria-labelledby="dialog-title-{uid}"
  aria-describedby={description ? `dialog-desc-${uid}` : undefined}
  onclose={handleClose}
  onclick={onBackdropClick}
>
  <div class="flex items-start justify-between gap-4 border-b border-border px-6 py-5">
    <div class="min-w-0">
      <h2 id="dialog-title-{uid}" class="font-display text-lg font-semibold tracking-tight">{title}</h2>
      {#if description}
        <p id="dialog-desc-{uid}" class="mt-1 text-[13px] text-muted">{description}</p>
      {/if}
    </div>
    <button
      type="button"
      class="-mr-2 -mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-dim transition-colors hover:bg-white/5 hover:text-fg"
      aria-label="Close dialog"
      onclick={handleClose}
    >
      <Icon name="x" size={16} />
    </button>
  </div>

  <div class="max-h-[70vh] overflow-y-auto px-6 py-5">
    {@render children()}
  </div>

  {#if footer}
    <div class="flex flex-wrap items-center justify-end gap-2 border-t border-border bg-surface-2/50 px-6 py-4">
      {@render footer()}
    </div>
  {/if}
</dialog>
