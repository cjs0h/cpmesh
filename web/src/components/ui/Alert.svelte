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

  const styles: Record<Tone, { box: string; icon: string }> = {
    info: { box: 'bg-cyan/25', icon: 'info' },
    success: { box: 'bg-mint/30', icon: 'check-circle' },
    warning: { box: 'bg-yellow/45', icon: 'alert-triangle' },
    danger: { box: 'bg-rose/25', icon: 'alert-circle' },
  };
</script>

<div
  class="flex items-start gap-3 rounded-md border-2 border-ink px-3.5 py-3 text-[13px] leading-relaxed text-ink shadow-sm animate-[fade-up_0.3s_var(--ease-out-expo)] {styles[tone].box} {className}"
  role={tone === 'danger' || tone === 'warning' ? 'alert' : 'status'}
>
  <span class="mt-0.5 shrink-0 text-ink">
    <Icon name={icon ?? styles[tone].icon} size={16} strokeWidth={2.5} />
  </span>
  <div class="min-w-0 flex-1">
    {#if title}<p class="font-head text-[13px]">{title}</p>{/if}
    <div class={title ? 'mt-0.5 text-ink/80' : ''}>{@render children()}</div>
  </div>
  {#if dismissible}
    <button type="button" class="-mr-1 -mt-1 rounded p-1 text-ink/60 transition-colors hover:text-ink" aria-label="Dismiss" onclick={ondismiss}>
      <Icon name="x" size={14} strokeWidth={2.5} />
    </button>
  {/if}
</div>
