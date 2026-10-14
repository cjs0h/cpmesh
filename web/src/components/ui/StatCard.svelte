<script lang="ts">
  import Icon from '../Icon.svelte';

  type Accent = 'accent' | 'cyan' | 'mint' | 'gold' | 'rose' | 'violet';

  interface Props {
    label: string;
    value: string | number;
    icon: string;
    /** Kept for call-site compatibility; stats are rendered monochrome. */
    accent?: Accent;
    caption?: string;
    /** Bar chart from values in 0–1. */
    trend?: number[];
    delay?: number;
    class?: string;
  }

  let { label, value, icon, accent: _accent, caption, trend, delay: _delay, class: className = '' }: Props = $props();
</script>

<div class="rounded-lg border border-border bg-surface p-5 {className}">
  <div class="flex items-center justify-between gap-3">
    <p class="text-[13px] font-medium text-muted">{label}</p>
    <span class="text-dim"><Icon name={icon} size={16} /></span>
  </div>
  <p class="mt-3 text-[28px] font-semibold leading-none tracking-tight text-fg tabular-nums">{value}</p>
  {#if caption}<p class="mt-2 text-xs text-dim">{caption}</p>{/if}

  {#if trend && trend.length > 0}
    <div class="mt-4 flex h-8 items-end gap-[3px]" aria-hidden="true">
      {#each trend as v, i (i)}
        <span class="flex-1 rounded-sm bg-ink" style="height: {Math.max(8, Math.min(100, v * 100))}%; opacity: {0.15 + (i / trend.length) * 0.85};"></span>
      {/each}
    </div>
  {/if}
</div>
