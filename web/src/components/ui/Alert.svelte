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
    info: { box: 'border-cyan/25 bg-cyan/8 text-fg', icon: 'info' },
    success: { box: 'border-mint/30 bg-mint/10 text-fg', icon: 'check-circle' },
    warning: { box: 'border-gold/30 bg-gold/10 text-fg', icon: 'alert-triangle' },
    danger: { box: 'border-rose/30 bg-rose/10 text-fg', icon: 'alert-circle' },
  };

  const iconTone: Record<Tone, string> = {
    info: 'text-cyan',
    success: 'text-mint',
    warning: 'text-gold',
    danger: 'text-rose',
  };
</script>

<div
  class="flex items-start gap-3 rounded-lg border px-3.5 py-3 text-[13px] leading-relaxed animate-[fade-up_0.3s_var(--ease-out-expo)] {styles[tone].box} {className}"
  role={tone === 'danger' || tone === 'warning' ? 'alert' : 'status'}
>
  <span class="mt-0.5 shrink-0 {iconTone[tone]}">
    <Icon name={icon ?? styles[tone].icon} size={16} />
  </span>
  <div class="min-w-0 flex-1">
    {#if title}<p class="font-semibold">{title}</p>{/if}
    <div class={title ? 'mt-0.5 text-muted' : ''}>{@render children()}</div>
  </div>
  {#if dismissible}
    <button type="button" class="-mr-1 -mt-1 rounded p-1 text-dim transition-colors hover:text-fg" aria-label="Dismiss" onclick={ondismiss}>
      <Icon name="x" size={14} />
    </button>
  {/if}
</div>
