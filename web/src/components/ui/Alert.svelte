<script lang="ts">
  import type { Snippet } from 'svelte';
  import Icon from '../Icon.svelte';

  type Tone = 'info' | 'success' | 'warning' | 'danger';

  interface Props {
    tone?: Tone;
    title?: string;
    icon?: string;
    dismissible?: boolean;
    ondismiss?: () => void;
    class?: string;
    children: Snippet;
  }

  let { tone = 'info', title, icon, dismissible = false, ondismiss, class: className = '', children }: Props = $props();

  const styles: Record<Tone, { box: string; icon: string; iconColor: string }> = {
    info: { box: 'border-border bg-bg-deep text-fg', icon: 'info', iconColor: 'text-muted' },
    success: { box: 'border-green-200 bg-green-50 text-green-900', icon: 'check-circle', iconColor: 'text-green-600' },
    warning: { box: 'border-amber-200 bg-amber-50 text-amber-900', icon: 'alert-triangle', iconColor: 'text-amber-600' },
    danger: { box: 'border-red-200 bg-red-50 text-red-900', icon: 'alert-circle', iconColor: 'text-red-600' },
  };
</script>

<div class="flex items-start gap-3 rounded-md border px-3.5 py-3 text-[13px] leading-relaxed {styles[tone].box} {className}" role={tone === 'danger' || tone === 'warning' ? 'alert' : 'status'}>
  <span class="mt-0.5 shrink-0 {styles[tone].iconColor}"><Icon name={icon ?? styles[tone].icon} size={15} /></span>
  <div class="min-w-0 flex-1">
    {#if title}<p class="font-medium">{title}</p>{/if}
    <div class={title ? 'mt-0.5 opacity-80' : ''}>{@render children()}</div>
  </div>
  {#if dismissible}
    <button type="button" class="-mr-1 -mt-1 rounded p-1 opacity-60 transition-opacity hover:opacity-100" aria-label="Dismiss" onclick={ondismiss}>
      <Icon name="x" size={14} />
    </button>
  {/if}
</div>
