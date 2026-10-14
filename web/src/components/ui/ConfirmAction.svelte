<script lang="ts">
  import Button from './Button.svelte';

  /**
   * Two-step destructive action: a trigger button that swaps to an inline
   * "Are you sure?" confirmation, so no modal is needed for small deletes.
   */
  interface Props {
    label?: string;
    icon?: string;
    confirmLabel?: string;
    prompt?: string;
    size?: 'xs' | 'sm' | 'md' | 'icon-sm';
    variant?: 'outline' | 'ghost' | 'danger-soft';
    loading?: boolean;
    disabled?: boolean;
    title?: string;
    class?: string;
    onconfirm: () => void | Promise<void>;
  }

  let {
    label = 'Delete',
    icon = 'trash',
    confirmLabel = 'Yes, delete',
    prompt = 'Are you sure?',
    size = 'sm',
    variant = 'outline',
    loading = false,
    disabled = false,
    title,
    class: className = '',
    onconfirm,
  }: Props = $props();

  let open = $state(false);
  let busy = $state(false);

  async function confirm() {
    busy = true;
    try {
      await onconfirm();
    } finally {
      busy = false;
      open = false;
    }
  }
</script>

{#if open}
  <span class="inline-flex items-center gap-2 animate-[fade-in_0.2s_ease-out] {className}">
    <span class="text-[12px] font-medium text-warning">{prompt}</span>
    <Button variant="danger" size={size === 'icon-sm' ? 'xs' : size} loading={busy || loading} onclick={confirm}>{confirmLabel}</Button>
    <Button variant="ghost" size={size === 'icon-sm' ? 'xs' : size} disabled={busy} onclick={() => (open = false)}>Cancel</Button>
  </span>
{:else}
  <Button
    {variant}
    {size}
    {icon}
    {disabled}
    {title}
    class="{variant !== 'danger-soft' ? 'hover:border-red-200 hover:text-danger' : ''} {className}"
    aria-label={size === 'icon-sm' ? label : undefined}
    onclick={() => (open = true)}
  >
    {#if size !== 'icon-sm'}{label}{/if}
  </Button>
{/if}
